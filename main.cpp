#include <iostream>
#include <unordered_map>

#if DEPLOYMENT
	#define NRS_PORTS { 4950, 3960 }
#else
	#define NRS_PORTS { 1234 }
#endif

#define ENABLE_SHADOW_REALM DEPLOYMENT
#define BANISH_U41_1_TO_SHADOW_REALM DEPLOYMENT

#define IS_LAN_DEPLOYMENT !DEPLOYMENT

#define MAX_PROXY_CONNECTIONS 100
#define PROXYING_FOR_LEGACY true
#define FORCE_PROXY_CONNECTIONS false

#define ENABLE_HTTP true
#define HTTP_PORT 4950

#define USERNAMES true

#include <crc32.hpp>
#include <crc32c.hpp>
/*#if IS_LAN_DEPLOYMENT
#include <dhcp.hpp>
#endif*/
#if ENABLE_HTTP
#include <HttpRequest.hpp>
#endif
#include <json.hpp>
#include <lzf.hpp>
#include <md5.hpp>
#include <MemoryRefReader.hpp>
#if IS_LAN_DEPLOYMENT
#include <netAdaptor.hpp>
#endif
#include <netInfo.hpp>
#include <Server.hpp>
#include <ServerServiceUdp.hpp>
#if ENABLE_HTTP
#include <ServerWebService.hpp>
#endif
#include <Socket.hpp>
#include <string.hpp>
#include <StringWriter.hpp>
#include <time.hpp>
#include <utility.hpp>

#ifdef DOCKER
#include <signal.h>
#endif

#if USE_DTLSBRIDGE
extern "C"
{
	// inputData may be modified. Returns true if input data could successfully be decoded as DTLS traffic.
	bool ReadData(uint8_t* inputData, size_t inputDataLength, uint8_t* pendingSendBuffer, size_t* pendingSendLength, uint8_t decryptedDataBuffer[4096], size_t* decryptedDataLength, const char* endpoint);
	void WriteData(const uint8_t* rawData, size_t rawDataLength, uint8_t* encryptedData, size_t* encryptedDataLength, const char* endpoint);
	void init();
}
#endif

using namespace soup;

static void udp_send(Socket& s, const SocketAddr& addr, const std::string& data, bool is_dtls)
{
#if USE_DTLSBRIDGE
	if (is_dtls)
	{
		uint8_t encryptedData[4096];
		size_t encryptedDataLength = 0;
		std::string endpoint = addr.toString();
		WriteData((const uint8_t*)data.data(), data.size(), encryptedData, &encryptedDataLength, endpoint.c_str());
		if (encryptedDataLength > 0)
		{
			s.udpServerSend(addr, (const char*)encryptedData, encryptedDataLength);
		}
		return;
	}
#endif
	s.udpServerSend(addr, data);
}

static bool is_u10_or_below(const std::string_view& salt)
{
	return salt == "6f7fd17e0eb641ab7"
		|| salt == "6f7fd17e0eb641ab6"
		|| salt == "3bd61b742870d0bb3"
		;
}

static bool is_u11_or_below(const std::string_view& salt)
{
	return salt == "6f7fd17e0eb641abC"
		|| is_u10_or_below(salt)
		;
}

static bool is_u15_or_below(const std::string_view& salt)
{
	return salt == "6f7fd17e0eb641abH"
		|| salt == "6f7fd17e0eb641abF"
		|| salt == "6f7fd17e0eb641abE"
		|| is_u11_or_below(salt)
		;
}

static bool is_u15_14_or_below(const std::string_view& salt)
{
	return salt == "6f7fd17e0eb641abN"
		|| is_u15_or_below(salt)
		;
}

static bool is_u27_or_below(const std::string_view& salt)
{
	return salt == "b471e49539930dc9b5a131e6247c7387D"
		|| salt == "b471e49539930dc9b5a131e6247c7387B"
		|| salt == "b471e49539930dc9b5a131e6247c7387A"
		|| salt == "6f7fd17e0eb641abQ"
		|| is_u15_14_or_below(salt)
		;
}

static bool is_u32_or_below(const std::string_view& salt)
{
	return salt == "b471e49539930dc9b5a131e6247c7387E"
		|| is_u27_or_below(salt)
		;
}

static bool is_u35_or_below(const std::string_view& salt)
{
	return salt == "b471e49539930dc9b5a131e6247c7387F"
		|| is_u32_or_below(salt)
		;
}

static uint64_t md5_checksum(const char* data, size_t size, const std::string_view& salt)
{
	md5::State st;
	st.append(data, size);
	st.append(salt.data(), salt.size());
	union {
		uint8_t digest[md5::DIGEST_BYTES];
		uint64_t chksum64;
	} u;
	st.finalise();
	st.getDigest(u.digest);
	return u.chksum64;
}

static std::string packData(const std::string& data, const std::string_view& salt)
{
	StringWriter sw;

	sw.skip(!is_u11_or_below(salt) ? 5 : 9); // placeholder for compression byte + CRC

	uint32_t magic = 0x80000000;
	sw.u32_le(magic);

	sw.str_lp<u16_le_t>(data);

	if (!is_u11_or_below(salt))
	{
		if (!is_u32_or_below(salt))
		{
			uint32_t initial = crc32c::hash((const uint8_t*)sw.data.data() + 5, sw.data.size() - 5);
			*(uint32_t*)(sw.data.data() + 1) = Endianness::toNetwork(crc32c::hash((const uint8_t*)salt.data(), salt.size(), initial));
		}
		else
		{
			uint32_t initial = crc32::hash((const uint8_t*)sw.data.data() + 5, sw.data.size() - 5);
			*(uint32_t*)(sw.data.data() + 1) = Endianness::toNetwork(crc32::hash((const uint8_t*)salt.data(), salt.size(), initial));	
		}
	}
	else
	{
		*(uint64_t*)(sw.data.data() + 1) = md5_checksum(sw.data.data() + 9, sw.data.size() - 9, salt);
	}

	//std::cout << "Server says: " << string::bin2hex(sw.data) << std::endl;

#if true
	{
		uint16_t decompressed_size = sw.data.size() - 1;
		uint8_t buffer[0x1000];
		if (decompressed_size <= 0x3F)
		{
			if (auto compressed_size = lzf::compress(sw.data.data() + 1, sw.data.size() - 1, buffer + 1, sizeof(buffer) - 1);
				compressed_size != 0 && (compressed_size + 1) < sw.data.size()
				)
			{
				buffer[0] = decompressed_size;
				return std::string((const char*)buffer, compressed_size + 1);
			}
		}
		else
		{
			if (auto compressed_size = lzf::compress(sw.data.data() + 1, sw.data.size() - 1, buffer + 2, sizeof(buffer) - 2);
				compressed_size != 0 && (compressed_size + 2) < sw.data.size()
				)
			{
				buffer[0] = (decompressed_size >> 6) | 0x80;
				buffer[1] = (decompressed_size & 0x3F) | 0xC0;
				return std::string((const char*)buffer, compressed_size + 2);
			}
		}
	}
#endif

	SOUP_MOVE_RETURN(sw.data);
}

template <typename T>
static void ser_str(T& s, const std::string_view& salt, std::string& str)
{
	if (is_u35_or_below(salt))
	{
		s.template str_lp<u32_le_t>(str);
	}
	else
	{
		uint32_t len = str.size();
		s.oml(len);
		s.str(len, str);
	}
}

struct AccountData
{
	native_u32_t reflexive_ip;
	native_u32_t local_ip;

	native_u16_t reflexive_port_client = 4955;
	native_u16_t reflexive_port_server = 4950;
	native_u16_t local_port_client = 4955;
	native_u16_t local_port_server = 4950;

	std::string_view salt;
	bool is_dtls;
#if ENABLE_SHADOW_REALM
	bool in_shadow_realm = false;
#endif

	uint8_t status; // presence state
	std::string presence;

	time_t last_nat_bind;

#if USERNAMES
	std::string username;
#endif

	bool isActive() const noexcept
	{
		return time::unixSecondsSince(last_nat_bind) <= 120;
	}

	void sendGameInvite(Socket& s, const std::string& inviter_acctId, const std::string& invitee_acctId, const std::string& session_info, const std::string& inviter_name, uint8_t bindingServerId = 0, uint8_t presence_state = 3)
	{
		StringWriter sw;
		{ uint8_t b = 0x7c /* 31 << 2 */; sw.u8(b); }
		sw.str(12, inviter_acctId);
		if (!is_u15_or_below(salt))
		{
			if (!is_u15_14_or_below(salt))
			{
				sw.u8(bindingServerId);
			}
			sw.str(12, invitee_acctId);
		}
		sw.u8(presence_state);
		ser_str(sw, this->salt, const_cast<std::string&>(session_info));
		ser_str(sw, this->salt, const_cast<std::string&>(inviter_name));
		std::string unk_str; ser_str(sw, this->salt, unk_str);
		udp_send(s, SocketAddr(this->reflexive_ip, this->reflexive_port_client), packData(sw.data, this->salt), this->is_dtls);
	}

	void sendSocialChange(Socket& s, uint8_t type, const std::string& json)
	{
		if (!is_u11_or_below(this->salt))
		{
			StringWriter sw;
			{ uint8_t b = 0xac; sw.u8(b); }
			sw.u8(type);
			ser_str(sw, this->salt, const_cast<std::string&>(json));
			udp_send(s, SocketAddr(this->reflexive_ip, this->reflexive_port_client), packData(sw.data, this->salt), this->is_dtls);
		}
	}

	void sendFriendRefresh(Socket& s, uint8_t unk = 9)
	{
		if (!is_u10_or_below(this->salt))
		{
			StringWriter sw;
			{ uint8_t b = 0x78; sw.u8(b); }
			sw.u8(unk);
			udp_send(s, SocketAddr(this->reflexive_ip, this->reflexive_port_client), packData(sw.data, this->salt), this->is_dtls);
		}
	}
};
static std::unordered_map<std::string, AccountData> account_map;

enum IntroductionType : uint8_t
{
	IT_FROM_PEER = 0,
	IT_TO_PROXY = 1,
	IT_VIA_PROXY = 2, // "potential proxy"
};

static void send_introduction(Socket& s, const std::string& from_acctId, const std::string& to_acctId, const SocketAddr& from_addr, const SocketAddr& to_addr, IntroductionType it, uint8_t task_id, const std::string_view& salt, bool is_dtls)
{
	StringWriter sw;
	if (!is_u10_or_below(salt)) // >= U11
	{
		{ uint8_t b = 0x70 /* 28 << 2 */; sw.u8(b); }
		sw.u8(task_id);
		if (!is_u15_or_below(salt))
		{
			uint32_t ip = from_addr.ip.getV4NativeEndian();
			uint16_t port = from_addr.getPort();

			ip ^= 0xAAAAAAAA;
			port ^= 0xAAAA;

			{ uint8_t b = it; sw.u8(b); }
			sw.str(12, from_acctId);
			sw.str(12, to_acctId);
			sw.u32_be(ip);
			sw.u16_le(port);
		}
		else
		{
			std::string tmp = string::bin2hexLower(from_acctId);
			ser_str(sw, salt, tmp);
			tmp = string::bin2hexLower(to_acctId);
			ser_str(sw, salt, tmp);
			tmp = from_addr.toString();
			ser_str(sw, salt, tmp);
		}
	}
	else
	{
		{ uint8_t b = 24 << 2; sw.u8(b); }
		std::string tmp = string::bin2hexLower(from_acctId);
		ser_str(sw, salt, tmp);
		tmp = string::bin2hexLower(to_acctId);
		ser_str(sw, salt, tmp);
		tmp = from_addr.toString();
		ser_str(sw, salt, tmp);
		tmp = std::string(1, task_id);
		ser_str(sw, salt, tmp);
	}
	udp_send(s, to_addr, packData(sw.data, salt), is_dtls);
}

static network_u32_t this_machine_ip = 0;
#if MAX_PROXY_CONNECTIONS > 0
struct Proxy : public ServerServiceUdp
{
	network_u32_t left_ip;
	network_u32_t right_ip;
	network_u16_t left_port;
	network_u16_t right_port;
	network_u16_t port;
	bool left_is_server;
	bool right_is_server;
	time_t last_traffic = 0;

	Proxy()
		: ServerServiceUdp(&staticCallback)
	{
	}

	static void staticCallback(Socket& s, SocketAddr&& addr, std::string&& data, ServerServiceUdp& srv)
	{
		static_cast<Proxy&>(srv).callback(s, std::move(addr), std::move(data));
	}

	void callback(Socket& s, SocketAddr&& addr, std::string&& data)
	{
		if (addr.ip.getV4() == left_ip /*&& addr.port == left_port*/)
		{
			left_port = addr.port;
			last_traffic = time::unixSeconds();
			s.udpServerSend(SocketAddr(right_ip, right_port), std::move(data));
		}
		else if (addr.ip.getV4() == right_ip /*&& addr.port == right_port*/)
		{
			right_port = addr.port;
			last_traffic = time::unixSeconds();
			s.udpServerSend(SocketAddr(left_ip, left_port), std::move(data));
		}
		else
		{
			std::cout << "Unsolicited traffic on proxy port " << Endianness::toNative(port) << " from " << addr.toString() << std::endl;
		}
	}
};
static Proxy proxies[MAX_PROXY_CONNECTIONS];

static network_u16_t get_proxy(network_u32_t left_ip, bool left_is_server, network_u32_t right_ip, bool right_is_server)
{
	if (left_ip == right_ip)
	{
		return 0;
	}
	for (auto& proxy : proxies)
	{
		if (proxy.left_ip == left_ip && proxy.right_ip == right_ip && proxy.left_is_server == left_is_server && proxy.right_is_server == right_is_server && time::unixSecondsSince(proxy.last_traffic) <= 60)
		{
			proxy.last_traffic = time::unixSeconds();
			return proxy.port;
		}
	}
	return 0;
}

static network_u16_t setup_proxying(network_u32_t left_ip, network_u16_t left_port, bool left_is_server, network_u32_t right_ip, network_u16_t right_port, bool right_is_server)
{
	if (left_ip == right_ip)
	{
		return 0;
	}
	Proxy* free_proxy = nullptr;
	for (auto& proxy : proxies)
	{
		if (proxy.left_ip == left_ip && proxy.right_ip == right_ip && proxy.left_is_server == left_is_server && proxy.right_is_server == right_is_server)
		{
			proxy.last_traffic = time::unixSeconds();
			return proxy.port;
		}
		if (free_proxy == nullptr && time::unixSecondsSince(proxy.last_traffic) > 60)
		{
			free_proxy = &proxy;
		}
	}
	if (free_proxy)
	{
		free_proxy->left_ip = left_ip;
		free_proxy->right_ip = right_ip;
		free_proxy->left_port = left_port;
		free_proxy->right_port = right_port;
		free_proxy->left_is_server = left_is_server;
		free_proxy->right_is_server = right_is_server;
		free_proxy->last_traffic = time::unixSeconds();
		return free_proxy->port;
	}
	return 0;
}
#endif

int main(int argc, const char** argv)
{
#if USE_DTLSBRIDGE
	init();
#endif

	Server serv;

	ServerServiceUdp srv([](Socket& s, SocketAddr&& addr, std::string&& data, ServerServiceUdp&)
	{
		bool is_dtls = false;
#if USE_DTLSBRIDGE
		{
			std::string data_copy = data;
			uint8_t pendingSend[4096];
			uint8_t decryptedData[4096];
			size_t pendingSendLength = 0;
			size_t decryptedDataLength = 0;
			std::string endpoint = addr.toString();
			is_dtls = ReadData((uint8_t*)data_copy.data(), data_copy.size(), pendingSend, &pendingSendLength, decryptedData, &decryptedDataLength, endpoint.c_str());
			if (pendingSendLength > 0)
			{
				s.udpServerSend(addr, (const char*)pendingSend, pendingSendLength);
			}
			if (decryptedDataLength != 0)
			{
				const uint8_t AESkey[] = { 0x63, 0x8C, 0x59, 0x2C, 0xE1, 0x57, 0xC2, 0x1B };
				if (decryptedDataLength == sizeof(AESkey) && memcmp(decryptedData, AESkey, sizeof(AESkey)) == 0)
				{
					uint8_t encryptedData[4096];
					size_t encryptedDataLength = 0;
					WriteData(AESkey, sizeof(AESkey), encryptedData, &encryptedDataLength, endpoint.c_str());
					if (encryptedDataLength > 0)
					{
						s.udpServerSend(addr, (const char*)encryptedData, encryptedDataLength);
					}
					//std::cout << addr.toString() << " - Sent AES key" << std::endl;
					return;
				}
				data = std::string((const char*)decryptedData, decryptedDataLength);
			}
			else if (is_dtls)
			{
				return;
			}
		}
#endif

		MemoryRefReader sr(data);

		uint8_t unk_byte;
		sr.u8(unk_byte);
		if (unk_byte != 0)
		{
			uint16_t expected_decompressed_size = unk_byte;
			if (unk_byte & 0x80)
			{
				expected_decompressed_size &= 0x3F;
				while (unk_byte & 0x40)
				{
					sr.u8(unk_byte);
					expected_decompressed_size <<= 6;
					expected_decompressed_size |= unk_byte & 0x3F;
				}
			}

			char buffer[0x1000];
			const auto decompressed_size = lzf::decompress(data.data() + sr.getPosition(), data.size() - sr.getPosition(), buffer, sizeof(buffer));
			if (decompressed_size != expected_decompressed_size)
			{
				std::cout << addr.toString() << " - Decompressed size mismatch (got " << decompressed_size << ", expected " << expected_decompressed_size << "): " << string::bin2hex(data) << std::endl;
				return;
			}
			data = std::string(buffer, decompressed_size);
			sr = MemoryRefReader(data);
		}

		//std::cout << addr.toString() << " > " << string::bin2hex(data) << std::endl;

		uint32_t chksum;
		sr.u32_be(chksum);
		//std::cout << "Recvd chksum: " << chksum << std::endl;

		uint32_t initial = crc32c::hash((const uint8_t*)data.data() + sr.getPosition(), data.size() - sr.getPosition(), 0);
		std::string_view salt = "b471e49539930dc9b5a131e6247c7387H"; // >= U41
		if (crc32c::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
		{
			salt = "b471e49539930dc9b5a131e6247c7387G"; // < U41 && >= U35.5
			if (crc32c::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
			{
				salt = "b471e49539930dc9b5a131e6247c7387F"; // < U35.5 && >= U33
				if (crc32c::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
				{
					initial = crc32::hash((const uint8_t*)data.data() + sr.getPosition(), data.size() - sr.getPosition(), 0);
					salt = "b471e49539930dc9b5a131e6247c7387E"; // < U33 && >= U28
					if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
					{
						salt = "b471e49539930dc9b5a131e6247c7387D"; // < U28 && >= U27
						if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
						{
							salt = "b471e49539930dc9b5a131e6247c7387B"; // < U27 && >= U23
							if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
							{
								salt = "b471e49539930dc9b5a131e6247c7387A"; // < U23 && >= U18.18
								if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
								{
									salt = "6f7fd17e0eb641abQ"; // < U18.18
									if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
									{
										salt = "6f7fd17e0eb641abN"; // ~ U15.14
										if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
										{
											salt = "6f7fd17e0eb641abH"; // ~ U15
											if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
											{
												salt = "6f7fd17e0eb641abF"; // ~ U13.4
												if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
												{
													salt = "6f7fd17e0eb641abE"; // ~ U13
													if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
													{
														chksum = Endianness::invert(chksum);
														uint32_t chksum_hi;
														sr.u32_le(chksum_hi);
														uint64_t chksum64 = (static_cast<uint64_t>(chksum_hi) << 32) | chksum;
														//std::cout << "chksum64 = " << std::hex << chksum64 << std::dec << std::endl;
														salt = "6f7fd17e0eb641abC"; // ~ U11
														if (md5_checksum(data.data() + sr.getPosition(), data.size() - sr.getPosition(), salt) != chksum64)
														{
															salt = "6f7fd17e0eb641ab7"; // ~ U10.8
															if (md5_checksum(data.data() + sr.getPosition(), data.size() - sr.getPosition(), salt) != chksum64)
															{
																salt = "6f7fd17e0eb641ab6"; // ~ U10.3
																if (md5_checksum(data.data() + sr.getPosition(), data.size() - sr.getPosition(), salt) != chksum64)
																{
																	salt = "3bd61b742870d0bb3"; // ~ U8
																	if (md5_checksum(data.data() + sr.getPosition(), data.size() - sr.getPosition(), salt) != chksum64)
																	{
																		std::cout << addr.toString() << " - Checksum mismatch: " << string::bin2hex(data) << std::endl;
																		return;
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		//std::cout << addr.toString() << " - salt = " << salt << std::endl;
#if DEPLOYMENT
		if (!is_dtls && !is_u32_or_below(salt))
		{
			std::cout << addr.toString() << " - Cleartext traffic from a post-DTLS version, ignoring" << std::endl;
			return;
		}
#endif

		uint8_t packet_id;
		sr.u8(packet_id);
		switch (packet_id)
		{
		case 0x54: // Test from client
		case 0x74: // Test from server
			{
				std::string acctId;
				uint64_t timestamp;
				uint32_t local_ip;
				uint16_t local_port;
				std::string local_addr_str;

				if (!is_u10_or_below(salt)) // >= U11
				{
					sr.str(12, acctId);
					if (!is_u27_or_below(salt)) // >= U28
					{
						sr.u64_le(timestamp);
					}
					else if (is_u11_or_below(salt)) // = U11
					{
						sr.skip(64); // NatHash
					}
					sr.u32_be(local_ip);
					sr.u16_le(local_port);
					if (!is_u15_or_below(salt))
					{
						ser_str(sr, salt, local_addr_str);
					}
				}
				else
				{
					// ',' acctId ',' NatHash
				}

#if ENABLE_SHADOW_REALM
				if (auto e = account_map.find(acctId); e != account_map.end())
				{
					if (e->second.in_shadow_realm)
					{
						break;
					}
				}
#endif

				//std::cout << addr.toString() << " - local_addr: " << IpAddr((native_u32_t)local_ip).toString() << ":" << local_port << std::endl;
				if (!is_u15_or_below(salt))
				{
					//std::cout << addr.toString() << " - local_addr_str: " << local_addr_str << std::endl;
				}

				uint32_t reflexive_ip = addr.ip.getV4NativeEndian();
				uint16_t reflexive_port = addr.getPort();

				reflexive_ip ^= 0xAAAAAAAA;
				reflexive_port ^= 0xAAAA;

				StringWriter sw;
				if (!is_u10_or_below(salt)) // >= U11
				{
					{ uint8_t b = 0x64 /* 25 << 2 */; sw.u8(b); }
					if (is_u15_14_or_below(salt))
					{
						// local addr is not xored in the request, but is expected to be xored in the response
						local_ip ^= 0xAAAAAAAA;
						local_port ^= 0xAAAA;
					}
					if (!is_u15_or_below(salt))
					{
						if (!is_u15_14_or_below(salt))
						{
							{ uint8_t bindingServerId = 0; sw.u8(bindingServerId); }
						}
						sw.u8(packet_id);
						sw.str(12, acctId);
						if (!is_u27_or_below(salt))
						{
							sw.u64_le(timestamp);
						}
						sw.u32_be(local_ip);
						sw.u16_le(local_port);
						ser_str(sw, salt, local_addr_str);
						sw.u32_be(reflexive_ip);
						sw.u16_le(reflexive_port);
					}
					else
					{
						sw.u32_be(reflexive_ip);
						sw.u16_le(reflexive_port);
						sw.u32_be(local_ip);
						sw.u16_le(local_port);
					}
				}
				else
				{
					{ uint8_t b = 39 << 2; sw.u8(b); }
					std::string tmp = addr.toString();
					ser_str(sw, salt, tmp);
				}
				udp_send(s, addr, packData(sw.data, salt), is_dtls);
			}
			break;

		case 0x42: // NAT bind for client
		case 0x62: // NAT bind for server
			{
				std::string acctId;
				uint32_t local_ip;
				uint16_t local_port;

				if (!is_u10_or_below(salt)) // >= U11
				{
					sr.str(12, acctId);
					if (is_u11_or_below(salt))
					{
						sr.skip(64); // NatHash
					}
					sr.u32_be(local_ip);
					sr.u16_le(local_port);
					local_ip ^= 0xAAAAAAAA;
					local_port ^= 0xAAAA;
					if (!is_u27_or_below(salt))
					{
						sr.skip(2);
					}
				}
				else // < U11
				{
					sr.skip(1); // ','
					std::string acctId_hex;
					sr.str(24, acctId_hex);
					acctId = string::hex2bin(acctId_hex);
					SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
					{
						std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
						return;
					}
					sr.skip(128); // NatHash
					SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
					{
						std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
						return;
					}
					SocketAddr sa;
					sa.fromString(data.substr(sr.getPosition()));
					local_ip = sa.ip.getV4NativeEndian();
					local_port = sa.getPort();
				}

				uint32_t reflexive_ip = addr.ip.getV4NativeEndian();
				uint16_t reflexive_port = addr.getPort();

				AccountData* data;
				if (auto e = account_map.find(acctId); e != account_map.end())
				{
					data = &e->second;
				}
				else
				{
					data = &account_map.emplace(acctId, AccountData{}).first->second;
				}
				data->reflexive_ip = reflexive_ip;
				data->local_ip = local_ip;
				data->salt = salt;
				data->is_dtls = is_dtls;
				if (packet_id == 0x42)
				{
					data->reflexive_port_client = reflexive_port;
					data->local_port_client = local_port;
					std::string presence;
					if (!is_u10_or_below(salt)) // >= U11
					{
						sr.u8(data->status);
						if (!is_u15_or_below(salt)) // >= U15.14
						{
							uint8_t num_proxy_connections = 0;
							sr.u8(num_proxy_connections);
							sr.skip(num_proxy_connections * (12 + 1)); // seems to be account id of target followed by 0x00
						}
						ser_str(sr, salt, presence);
					}

					//std::cout << addr.toString() << "#" << string::bin2hexLower(acctId) << " - NAT bound for client " << string::bin2hex(acctId) << std::endl;
					//std::cout << addr.toString() << "#" << string::bin2hexLower(acctId) << " - Client Local Addr: " << IpAddr((native_u32_t)local_ip).toString() << ":" << local_port << std::endl;
					//std::cout << addr.toString() << "#" << string::bin2hexLower(acctId) << " - Status: " << (int)data->status << std::endl;
					if (
						presence != data->presence
#if ENABLE_SHADOW_REALM
						&& !data->in_shadow_realm
#endif
						)
					{
						data->presence = std::move(presence);
						std::cout << addr.toString() << "#" << string::bin2hexLower(acctId) << " - Updated presence: " << data->presence << std::endl;
#if ENABLE_SHADOW_REALM && BANISH_U41_1_TO_SHADOW_REALM
						if (data->presence.find("{\"l\":") != std::string::npos || data->presence.find(",\"l\":") != std::string::npos)
						{
							data->in_shadow_realm = true;
							std::cout << addr.toString() << "#" << string::bin2hexLower(acctId) << " - Banished to the shadow realm" << std::endl;
						}
#endif
					}

					//data->sendGameInvite(s, acctId, acctId, R"({})", "Welcome :)", 0, 0);
				}
				else
				{
					//std::cout << addr.toString() << "#" << string::bin2hexLower(acctId) << " - Server Local Addr: " << IpAddr((native_u32_t)local_ip).toString() << ":" << local_port << std::endl;

					data->reflexive_port_server = reflexive_port;
					data->local_port_server = local_port;
				}
				data->last_nat_bind = time::unixSeconds();

				StringWriter sw;
				if (!is_u10_or_below(salt)) // >= U11
				{
					{ uint8_t b = 0x60 /* 24 << 2 */; sw.u8(b); }
					if (!is_u15_or_below(salt))
					{
						{ uint8_t b = (MAX_PROXY_CONNECTIONS > 0 ? 1 : 0); sw.u8(b); } // 0 = no proxying, 1 = yes proxying
						if (!is_u27_or_below(salt)) // 2022.04.29.12.53 (~ U31.5) crashes when this field is not given.
						{
							{ uint8_t b = (packet_id == 0x42 ? 1 : 0); sw.u8(b); }
						}
					}
					if (!is_u11_or_below(salt))
					{
						reflexive_ip ^= 0xAAAAAAAA;
						reflexive_port ^= 0xAAAA;
					}
					sw.u32_be(reflexive_ip);
					sw.u16_le(reflexive_port);
				}
				else
				{
					{ uint8_t b = 37 << 2; sw.u8(b); }
					// U8 does not need anything in the response, but U10.8 needs this:
					std::string tmp = addr.toString();
					ser_str(sw, salt, tmp);
				}
				udp_send(s, addr, packData(sw.data, salt), is_dtls);

#if USERNAMES
				if (data->username.empty()
					&& data->presence.find("\"hid\":\"" + string::bin2hexLower(acctId)) != std::string::npos
					)
				{
					for (const uint16_t& port : NRS_PORTS)
					{
						send_introduction(s, "333333333333", acctId, SocketAddr(this_machine_ip, (native_u16_t)port), SocketAddr(data->reflexive_ip, data->reflexive_port_server), IT_FROM_PEER, 69, salt, is_dtls);
						break;
					}
				}
#endif
			}
			break;

		case 0x55: // Logout
			{
				std::string acctId;
				if (!is_u10_or_below(salt)) // >= U11
				{
					sr.str(12, acctId);
					if (is_u11_or_below(salt))
					{
						// NatHash
					}
				}
				else
				{
					sr.skip(1); // ','
					std::string acctId_hex;
					sr.str(24, acctId_hex);
					acctId = string::hex2bin(acctId_hex);
					SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
					{
						std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
						return;
					}
					//sr.skip(128); // NatHash
				}
				account_map.erase(acctId);
				std::cout << addr.toString() << "#" << string::bin2hexLower(acctId) << " - Logged out" << std::endl;
			}
			break;

		case 0x70: // Fast presence query
		case 0x50: // Rich presence query
			if (!is_u10_or_below(salt)) // >= U11
			{
				std::string acctId;
				sr.str(12, acctId);
				if (is_u11_or_below(salt))
				{
					sr.skip(64); // NatHash
				}
				uint8_t task_id;
				sr.u8(task_id);
				uint8_t num_queries = 0;
				sr.u8(num_queries);

#if ENABLE_SHADOW_REALM
				bool in_shadow_realm;
				{
					auto e = account_map.find(acctId);
					in_shadow_realm = e != account_map.end() && e->second.in_shadow_realm;
				}
#endif

				StringWriter sw;
				{ uint8_t b = 0x6c; sw.u8(b); }
				sw.u8(task_id);
				{ uint8_t b = (packet_id == 0x50 ? 1 : 0); sw.u8(b); }
				sw.u8(num_queries);
				while (num_queries--)
				{
					std::string query;
					sr.str(12, query);
					sw.str(12, query);
					if (auto e = account_map.find(query); e != account_map.end())
					{
						if (e->second.isActive())
						{
#if ENABLE_SHADOW_REALM
							if (!in_shadow_realm)
#endif
							{
								sw.u8(e->second.status);
								if (packet_id == 0x50)
								{
									ser_str(sw, salt, e->second.presence);
								}
								continue;
							}
						}
						else
						{
							account_map.erase(e);
						}
					}
					{ uint8_t b = 0; sw.u8(b); }
					if (packet_id == 0x50)
					{
						std::string str;
						ser_str(sw, salt, str);
					}
				}
				udp_send(s, addr, packData(sw.data, salt), is_dtls);
			}
			else
			{
				// Not used in U8 afaict
				std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			}
			break;

			// "Resolve pending punchthroughs"
		case 0x52: // Query client addresses
		case 0x72: // Query server addresses
			//std::cout << addr.toString() << " - Request resolve pending punchthroughs" << std::endl;
			if (!is_u10_or_below(salt)) // >= U11
			{
#if ENABLE_SHADOW_REALM
				std::string acctId;
				sr.str(12, acctId);
				if (auto e = account_map.find(acctId); e != account_map.end())
				{
					if (e->second.in_shadow_realm)
					{
						break;
					}
				}
#else
				sr.skip(12); // acctId
#endif
				if (is_u11_or_below(salt))
				{
					sr.skip(64); // NatHash
				}
				uint8_t task_id;
				sr.u8(task_id);
				sr.skip(1); // num queries?
				std::string query;
				sr.str(12, query);
				//std::cout << addr.toString() << " - Resolving " << string::bin2hexLower(query) << std::endl;
				if (auto e = account_map.find(query); e != account_map.end())
				{
					if (e->second.isActive())
					{
						StringWriter sw;
						{ uint8_t b = 0x68; sw.u8(b); }
						sw.u8(task_id);
						{ uint8_t b = 1; sw.u8(b); } // num results
						sw.str(12, query); // result 0 account id
						if (!is_u32_or_below(salt))
						{
							{ uint8_t b = 0x81; sw.u8(b); } // result 0 bitflags
						}
						else
						{
							{ uint8_t b = 4; sw.u8(b); } // result 0 bitflags
						}
						{
#if FORCE_PROXY_CONNECTIONS
							uint32_t masked_ip = SOUP_IPV4(10, 0, 0, 0) ^ 0xAAAAAAAA;
#else
							uint32_t masked_ip = e->second.reflexive_ip ^ 0xAAAAAAAA;
#endif
							sw.u32_be(masked_ip);
						}
						{
							uint16_t masked_port = ((packet_id & 0x20) ? e->second.reflexive_port_server : e->second.reflexive_port_client) ^ 0xAAAA;
							sw.u16_le(masked_port);
						}
						{
#if FORCE_PROXY_CONNECTIONS
							uint32_t masked_ip = SOUP_IPV4(10, 0, 0, 0) ^ 0xAAAAAAAA;
#else
							uint32_t masked_ip = e->second.local_ip ^ 0xAAAAAAAA;
#endif
							sw.u32_be(masked_ip);
						}
						{
							uint16_t masked_port = ((packet_id & 0x20) ? e->second.local_port_server : e->second.local_port_client) ^ 0xAAAA;
							sw.u16_le(masked_port);
						}
						udp_send(s, addr, packData(sw.data, salt), is_dtls);
					}
					else
					{
						account_map.erase(e);
					}
				}
			}
			else
			{
				sr.skip(1); // ','
			#if false
				std::string acctId_hex;
				sr.str(24, acctId_hex);
				std::string acctId = string::hex2bin(acctId_hex);
			#else
				sr.skip(24);
			#endif
				SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
				{
					std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
					return;
				}
				sr.skip(128); // NatHash
				SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
				{
					std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
					return;
				}
				std::string task_id; sr.str(1, task_id);
				sr.skip(1); // ','
				auto arr = string::explode(data.substr(sr.getPosition()), ',');
				std::string res;
				for (const auto& target_hex : arr)
				{
					const auto target = string::hex2bin(target_hex);
					res.append(target_hex);
					res.push_back(',');
					if (auto e = account_map.find(target); e != account_map.end())
					{
						if (e->second.isActive())
						{
#if MAX_PROXY_CONNECTIONS > 0 && PROXYING_FOR_LEGACY
							if (auto proxy_port = get_proxy(addr.ip.getV4(), false, Endianness::toNetwork(e->second.reflexive_ip), (packet_id & 0x20)))
							{
								res.append(IpAddr(this_machine_ip).toString());
								res.push_back(',');
								res.append(std::to_string(Endianness::toNative(proxy_port)));
							}
							else if (auto proxy_port = get_proxy(Endianness::toNetwork(e->second.reflexive_ip), (packet_id & 0x20), addr.ip.getV4(), false))
							{
								res.append(IpAddr(this_machine_ip).toString());
								res.push_back(',');
								res.append(std::to_string(Endianness::toNative(proxy_port)));
							}
							else
#endif
							{
#if FORCE_PROXY_CONNECTIONS
								res.append("10.0.0.0");
#else
								res.append(IpAddr(e->second.reflexive_ip).toString());
#endif
								res.push_back(',');
								res.append(std::to_string((packet_id & 0x20) ? e->second.reflexive_port_server : e->second.reflexive_port_client));
								res.append(",priv,");
#if FORCE_PROXY_CONNECTIONS
								res.append("10.0.0.0");
#else
								res.append(IpAddr(e->second.local_ip).toString());
#endif
								res.push_back(',');
								res.append(std::to_string((packet_id & 0x20) ? e->second.local_port_server : e->second.local_port_client));
							}
							res.push_back(',');
							continue;
						}
						account_map.erase(e);
					}
					res.append(",0,0,");
				}
				if (!res.empty())
				{
					res.pop_back();
					StringWriter sw;
					{ uint8_t b = 28 << 2; sw.u8(b); }
					ser_str(sw, salt, task_id);
					ser_str(sw, salt, res);
					udp_send(s, addr, packData(sw.data, salt), is_dtls);
				}
			}
			break;

		case 0x43: // Client introduction request
		case 0x49: // Relayed client introduction request
		case 0x63: // Server introduction request
		case 0x69: // Relayed server introduction request
			//std::cout << addr.toString() << " - Introduction request " << string::hex(packet_id) << std::endl;
			{
				std::string acctId;
				uint8_t task_id;
				std::string target;

				if (!is_u10_or_below(salt)) // >= U11
				{
					sr.str(12, acctId);
					if (is_u11_or_below(salt))
					{
						sr.skip(64); // NatHash
					}
					sr.u8(task_id);
					sr.str(12, target);
				}
				else
				{
					sr.skip(1); // ','
					std::string acctId_hex;
					sr.str(24, acctId_hex);
					acctId = string::hex2bin(acctId_hex);
					SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
					{
						std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
						return;
					}
					sr.skip(128); // NatHash
					SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
					{
						std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
						return;
					}
					sr.u8(task_id);
					sr.skip(1); // ','
					std::string target_hex;
					sr.str(24, target_hex);
					target = string::hex2bin(target_hex);
					SOUP_IF_UNLIKELY (sr.hasMore())
					{
						std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
						return;
					}
				}

				native_u32_t local_ip = 0;
				native_u16_t local_port;
				bool from_server = false;
				const bool to_server = (packet_id & 0x20);
				if (auto e = account_map.find(acctId); e != account_map.end())
				{
#if ENABLE_SHADOW_REALM
					if (e->second.in_shadow_realm)
					{
						break;
					}
#endif
					local_ip = e->second.local_ip;
					from_server = (addr.getPort() == e->second.reflexive_port_server);
					local_port = (from_server ? e->second.local_port_server : e->second.local_port_client);
				}

				if (auto e = account_map.find(target); e != account_map.end())
				{
					if (e->second.isActive())
					{
						SocketAddr to_addr(e->second.reflexive_ip, to_server ? e->second.reflexive_port_server : e->second.reflexive_port_client);
#if FORCE_PROXY_CONNECTIONS
						// For emulation's sake
						send_introduction(s, acctId, target, SocketAddr(SOUP_IPV4_NWE(10, 0, 0, 0), addr.port), to_addr, IT_FROM_PEER, task_id, e->second.salt, e->second.is_dtls);
#else
						if (local_ip)
						{
							// This might not be entirely faithful but sometimes the correct LAN address is not detected, so also trying this the other way around should help.
							send_introduction(s, acctId, target, SocketAddr(local_ip, local_port), to_addr, IT_FROM_PEER, task_id, e->second.salt, e->second.is_dtls);
						}
						send_introduction(s, acctId, target, addr, to_addr, IT_FROM_PEER, task_id, e->second.salt, e->second.is_dtls);
#endif
						std::cout << addr.toString() << "#" << string::bin2hexLower(acctId) << " - Introduced to " << to_addr.toString() << "#" << string::bin2hexLower(target);
#if MAX_PROXY_CONNECTIONS > 0 && PROXYING_FOR_LEGACY
						if (is_u15_or_below(salt)) // < U15.14
						{
							// Check if other party already reserved a proxy port for us
							network_u16_t proxy_port = get_proxy(to_addr.ip.getV4(), to_server, addr.ip.getV4(), from_server);
							if (proxy_port == 0)
							{
								proxy_port = setup_proxying(addr.ip.getV4(), addr.port, from_server, to_addr.ip.getV4(), to_addr.port, to_server);
							}
							if (proxy_port != 0)
							{
								std::cout << " with proxy port " << Endianness::toNative(proxy_port) << " in reserve";
								send_introduction(s, acctId, target, SocketAddr(this_machine_ip, proxy_port), to_addr, IT_FROM_PEER, task_id, e->second.salt, e->second.is_dtls);
							}
						}
#endif
						std::cout << std::endl;
					}
					else
					{
						account_map.erase(e);
					}
				}
			}
			break;

#if MAX_PROXY_CONNECTIONS > 0
		case 0x78: // Proxy request
			if (!is_u15_or_below(salt)) // >= U15.14
			{
				std::string acctId;
				sr.str(12, acctId);
				uint8_t task_id;
				sr.u8(task_id);
				std::string target;
				sr.str(12, target);
				if (auto e = account_map.find(target); e != account_map.end())
				{
					if (e->second.isActive())
					{
						SocketAddr to_addr(e->second.reflexive_ip, e->second.reflexive_port_server);
						if (auto proxy_port = setup_proxying(addr.ip.getV4(), addr.port, false, to_addr.ip.getV4(), to_addr.port, true))
						{
							send_introduction(s, target, acctId, SocketAddr(this_machine_ip, proxy_port), addr, IT_TO_PROXY, task_id, salt, is_dtls);
							send_introduction(s, acctId, target, SocketAddr(this_machine_ip, proxy_port), to_addr, IT_VIA_PROXY, task_id, e->second.salt, e->second.is_dtls);
							std::cout << addr.toString() << "#" << string::bin2hexLower(acctId) << " - Obtained proxy port " << Endianness::toNative(proxy_port) << " to connect to " << string::bin2hexLower(target) << std::endl;
						}
					}
					else
					{
						account_map.erase(e);
					}
				}
			}
			else
			{
				std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			}
			break;
#endif

		case 0x76: // Game invite
		case 0x79: // Relayed game invite
			if (!is_u10_or_below(salt)) // >= U11 (it is unclear if U11 actually uses this packet because I can't find a way to actually send an invite...)
			{
				std::string acctId;
				sr.str(12, acctId);
#if ENABLE_SHADOW_REALM
				if (auto e = account_map.find(acctId); e != account_map.end())
				{
					if (e->second.in_shadow_realm)
					{
						break;
					}
				}
#endif
				if (is_u11_or_below(salt))
				{
					sr.skip(64); // NatHash
				}
				uint8_t bindingServerId = 0;
				if (!is_u15_14_or_below(salt))
				{
					sr.u8(bindingServerId);
				}
				std::string target;
				sr.str(12, target);
				uint8_t presence_state;
				sr.u8(presence_state);
				std::string session_info;
				ser_str(sr, salt, session_info);
				std::string inviter_name;
				ser_str(sr, salt, inviter_name);
				std::string unk_str;
				ser_str(sr, salt, unk_str);
				SOUP_UNUSED(unk_str);
				//std::cout << addr.toString() << " - " << inviter_name << " (" << string::bin2hex(acctId) << ") sending invite to " << string::bin2hex(target) << std::endl;
				if (auto e = account_map.find(target); e != account_map.end())
				{
					if (e->second.isActive())
					{
						e->second.sendGameInvite(s, acctId, target, session_info, inviter_name, bindingServerId, presence_state);
						break;
					}
					account_map.erase(e);
				}
				if (!is_u15_14_or_below(salt)) // Invite responses were introduced some time after U15.14
				{
					// Send game invite response with status 0 for offline
					StringWriter sw;
					{ uint8_t b = 0xa4; sw.u8(b); }
					sw.str(12, acctId);
					sw.str(12, target);
					uint8_t status = 0;
					sw.u8(status);
					udp_send(s, addr, packData(sw.data, salt), is_dtls);
				}
			}
			else
			{
				// Not used in U8 afaict
				std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			}
			break;

		case 0x56: // Game invite response
			if (!is_u15_14_or_below(salt))
			{
				std::string acctId;
				sr.str(12, acctId);
#if ENABLE_SHADOW_REALM
				if (auto e = account_map.find(acctId); e != account_map.end())
				{
					if (e->second.in_shadow_realm)
					{
						break;
					}
				}
#endif
				std::string target;
				sr.str(12, target);
				uint8_t status; // 1 = received. 3 = declined. 4 = failed to join.
				sr.u8(status);
				if (auto e = account_map.find(target); e != account_map.end())
				{
					if (e->second.isActive())
					{
						StringWriter sw;
						{ uint8_t b = 0xa4; sw.u8(b); }
						sw.str(12, target);
						sw.str(12, acctId);
						sw.u8(status);
						udp_send(s, SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_server), packData(sw.data, e->second.salt), e->second.is_dtls);
					}
					else
					{
						account_map.erase(e);
					}
				}
			}
			else
			{
				std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			}
			break;

		case 0x6a: // Send social change (when accepting a friend request or removing a friend in U39 and below; done via IRC nowadays)
			if (!is_u11_or_below(salt))
			{
				std::string acctId; sr.str(12, acctId);
				uint8_t type; sr.u8(type); // 29 = accept friend request, 30 = remove friend
				uint8_t num_changes = 0; sr.u8(num_changes);
				while (num_changes--)
				{
					std::string target; sr.str(12, target);
					std::string json; ser_str(sr, salt, json);
					if (auto e = account_map.find(target); e != account_map.end())
					{
						if (e->second.isActive())
						{
							e->second.sendSocialChange(s, type, json);
							std::cout << addr.toString() << "#" << string::bin2hexLower(acctId) << " - Sent social change " << (int)type << " " << json << " to " << SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_client).toString() << "#" << string::bin2hexLower(target) << std::endl;
						}
						else
						{
							account_map.erase(e);
						}
					}
				}
			}
			else
			{
				// Not used in U11 or below afaict
				std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			}
			break;

		case 0x73: // Request friend refresh (when sending a friend request in U39 and below; done via IRC nowadays)
			if (!is_u10_or_below(salt)) // >= U11
			{
				std::string acctId;
				uint8_t unk = 0x05;
				uint8_t num_targets = 1;

				sr.str(12, acctId);
				if (is_u11_or_below(salt))
				{
					sr.skip(64); // NatHash
				}
				else
				{
					sr.u8(unk); // always 0x09 ?
					sr.u8(num_targets);
				}

				while (num_targets--)
				{
					std::string target; sr.str(12, target);
					// In U11, the target account id seems to be followed by 0x05 instead of 0x09
					if (auto e = account_map.find(target); e != account_map.end())
					{
						if (e->second.isActive())
						{
							e->second.sendFriendRefresh(s, unk);
							std::cout << addr.toString() << "#" << string::bin2hexLower(acctId) << " - Sent friend request refresh " << (int)unk << " to " << SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_client).toString() << "#" << string::bin2hexLower(target) << std::endl;
						}
						else
						{
							account_map.erase(e);
						}
					}
				}
			}
			else
			{
				// Not used in < U11 afaict
				std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			}
			break;

		case 0x00:
			{
				std::string message = data.substr(sr.getPosition());
				if (message.size() > 3 && message[0] == 0 && message[1] == 0 && (uint8_t)message[2] == (uint8_t)0x80)
				{
					// P2P introduction
					// 00000080 15 02 74 <taskId> <platformFamily?> <acctId> <str:sessionInfoJson>

					/*size_t pos = message.rfind("{\""); // JSON is not nested afaict, so this should be a good way to find the start.
					if (pos != std::string::npos)
					{
						std::cout << addr.toString() << " - Coaxed into providing more information: " << message.substr(pos) << std::endl;
					}
					else
					{
						// No session info json provided
					}*/

#if USERNAMES
					std::string hostName;
					if (size_t pos = message.find(R"("hostName":)"); pos != std::string::npos)
					{
						pos += 11;
						if (auto j = json::decode(message.data() + pos, message.size() - pos); j && j->isStr())
						{
							hostName = std::move(j->reinterpretAsStr().value);
						}
					}
					if (!hostName.empty())
					{
						if (size_t pos = message.find(R"("hostId":)"); pos != std::string::npos)
						{
							pos += 9;
							if (auto j = json::decode(message.data() + pos, message.size() - pos); j && j->isStr())
							{
								std::string hostId = string::hex2bin(j->reinterpretAsStr().value);
								if (auto e = account_map.find(hostId); e != account_map.end())
								{
									std::cout << addr.toString() << " - Provided username for " << j->reinterpretAsStr().value << ": " << hostName << std::endl;
									e->second.username = std::move(hostName);
								}
							}
						}
					}
#endif
				}
				else
				{
					std::cout << addr.toString() << " - Custom message: " << message << std::endl;
					auto arr = string::explode(message, ',');
					if (arr.size() == 3)
					{
						if (auto e = account_map.find(string::hex2bin(arr[2])); e != account_map.end())
						{
							if (e->second.isActive())
							{
								if (arr[0] == "addPendingFriend")
								{
									e->second.sendFriendRefresh(s, 9);
								}
								else if (arr[0] == "addFriend")
								{
									//e->second.sendSocialChange(s, 29, "{\"id\":\"" + arr[1] + "\",\"avatarImage\":\"\",\"level\":0}");
									//e->second.sendSocialChange(s, 29, "{\"id\":\"" + arr[1] + "\"}");
									e->second.sendFriendRefresh(s, 9); // Unfaithful, but this way the avatarImage and level don't get reset by this notification.
								}
								else if (arr[0] == "removeFriend")
								{
									e->second.sendSocialChange(s, 30, "{\"id\":\"" + arr[1] + "\"}");
								}
							}
							else
							{
								account_map.erase(e);
							}
						}
					}
				}
			}
			break;

		default:
			std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			break;
		}
	});

	IpAddr bind_addr;
#if IS_LAN_DEPLOYMENT
	for (const auto& ad : netAdaptor::getAll())
	{
		//if (auto info = dhcp::requestInfo(ad.ip_addr); info.isValid())
		if (ad.name.find("Virtual") == std::string::npos)
		{
			bind_addr = ad.ip_addr;
			std::cout << "Using " << ad.name << " (" << bind_addr.toString() << ")" << std::endl;
			break;
		}
	}
#endif

	this_machine_ip = bind_addr.getV4();
	if (this_machine_ip == 0)
	{
		auto addr = netInfo::getPublicAddressV4();
		std::cout << "This machine's IP address: " << addr.toString() << std::endl;
		this_machine_ip = addr.getV4();
	}

	for (const uint16_t& port : NRS_PORTS)
	{
		if (!serv.bindUdp(bind_addr, port, &srv))
		{
			std::cout << "Failed to bind UDP/" << port << std::endl;
			return 1;
		}
		std::cout << "Bound UDP/" << port << std::endl;
	}

#if MAX_PROXY_CONNECTIONS > 0
	uint16_t port = 4200;
	for (auto& proxy : proxies)
	{
		while (!serv.bindUdp(bind_addr, port, &proxy))
		{
			port += 3;
		}
		proxy.port = Endianness::toNetwork(port);
		port += 3;
	}
#endif

#if ENABLE_HTTP
	ServerWebService web_srv([](Socket& s, HttpRequest&& req, ServerWebService&)
	{
		if (req.path == "/")
		{
			//ServerWebService::sendHtml(s, string::fromFile("index.html"));
			ServerWebService::sendText(s,
				"Welcome to this deployment of e-nrs!\r\n"
				"\r\n"
				"Available HTTP endpoints:\r\n"
				"- /api/stats\r\n"
				"- /api/me\r\n"
				"- /api/me/accounts\r\n"
				"- /api/account/:id\r\n"
			);
		}
		else if (req.path == "/api/stats")
		{
			JsonObject obj;
			{
				uint32_t allocated_accounts = 0;
				uint32_t active_accounts = 0;
				for (auto it = account_map.begin(); it != account_map.end(); ++it)
				{
					++allocated_accounts;
					if (it->second.isActive())
					{
						++active_accounts;
					}
				}
				obj.add("allocated_accounts", allocated_accounts);
				obj.add("active_accounts", active_accounts);
			}
#if MAX_PROXY_CONNECTIONS > 0
			{
				uint32_t active_proxies = 0;
				for (const auto& proxy : proxies)
				{
					if (time::unixSecondsSince(proxy.last_traffic) <= 60)
					{
						++active_proxies;
					}
				}
				obj.add("active_proxies", active_proxies);
			}
			obj.add("total_proxies", MAX_PROXY_CONNECTIONS);
#endif
			ServerWebService::sendText(s, obj.encodePretty());
		}
		else if (req.path == "/api/me")
		{
			ServerWebService::sendText(s, s.peer.ip.toString());
		}
		else if (req.path == "/api/me/accounts")
		{
			const auto reflexive_ip = s.peer.ip.getV4NativeEndian();
			JsonArray arr;
			for (auto it = account_map.begin(); it != account_map.end(); ++it)
			{
				if (it->second.reflexive_ip == reflexive_ip && it->second.isActive())
				{
					arr.children.emplace_back(soup::make_unique<JsonString>(string::bin2hexLower(it->first)));
				}
			}
			ServerWebService::sendText(s, arr.encodePretty());
		}
		else if (req.path.substr(0, 13) == "/api/account/")
		{
			JsonObject obj;
			if (auto e = account_map.find(string::hex2bin(req.path.substr(13))); e != account_map.end())
			{
				if (e->second.isActive())
				{
					// Data available via NRS
					obj.add("reflexive_ip", e->second.reflexive_ip);
					obj.add("reflexive_port_client", e->second.reflexive_port_client);
					obj.add("reflexive_port_server", e->second.reflexive_port_server);
					obj.add("local_ip", e->second.local_ip);
					obj.add("local_port_client", e->second.local_port_client);
					obj.add("local_port_server", e->second.local_port_server);
					obj.add("status", e->second.status);
					obj.add("presence", e->second.presence);
#if USERNAMES
					// Data available via SNS and conditionally via P2P
					if (!e->second.username.empty())
					{
						obj.add("username", e->second.username);
					}
#endif
				}
			}
			ServerWebService::sendText(s, obj.encodePretty());
		}
		else
		{
			ServerWebService::send404(s);
		}
	});
	if (serv.bind(bind_addr, HTTP_PORT, &web_srv))
	{
		std::cout << "Bound TCP/" << HTTP_PORT << " for HTTP" << std::endl;
	}
	else
	{
		std::cout << "Failed to bind TCP/" << HTTP_PORT << " for HTTP" << std::endl;
	}
#endif

#ifdef DOCKER
	// Ctrl+C not killing your software? According to the professional ChatGPTs hired by Docker Inc, it's not an issue. Why? Because there's a workaround!
	signal(SIGTERM, [](int) { exit(0); });
#endif

	serv.run();
}
