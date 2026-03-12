#include <iostream>
#include <unordered_map>

#include <crc32.hpp>
#include <crc32c.hpp>
#include <lzf.hpp>
#include <MemoryRefReader.hpp>
#include <Server.hpp>
#include <ServerServiceUdp.hpp>
#include <Socket.hpp>
#include <string.hpp>
#include <StringWriter.hpp>
#include <time.hpp>
#include <utility.hpp>

#ifdef DOCKER
#include <signal.h>
#endif

using namespace soup;

static bool is_u27_or_below(const std::string_view& salt)
{
	return salt == "b471e49539930dc9b5a131e6247c7387D"
		|| salt == "b471e49539930dc9b5a131e6247c7387B"
		|| salt == "b471e49539930dc9b5a131e6247c7387A"
		;
}

static bool is_u32_or_below(const std::string_view& salt)
{
	return salt == "b471e49539930dc9b5a131e6247c7387E"
		|| is_u27_or_below(salt)
		;
}

static std::string packData(const std::string& data, const std::string_view& salt)
{
	StringWriter sw;

	sw.skip(5); // placeholder for compression byte + CRC

	uint32_t magic = 0x80000000;
	sw.u32_le(magic);

	sw.str_lp<u16_le_t>(data);

	if (is_u32_or_below(salt))
	{
		uint32_t initial = crc32::hash((const uint8_t*)sw.data.data() + 5, sw.data.size() - 5);
		*(uint32_t*)(sw.data.data() + 1) = Endianness::toNetwork(crc32::hash((const uint8_t*)salt.data(), salt.size(), initial));	
	}
	else
	{
		uint32_t initial = crc32c::hash((const uint8_t*)sw.data.data() + 5, sw.data.size() - 5);
		*(uint32_t*)(sw.data.data() + 1) = Endianness::toNetwork(crc32c::hash((const uint8_t*)salt.data(), salt.size(), initial));
	}

	//std::cout << "Server says: " << string::bin2hex(sw.data) << std::endl;

#if true
	if (uint16_t decompressed_size = sw.data.size() - 1;
		decompressed_size > 0x3F
		)
	{
		uint8_t buffer[0x1000];
		if (auto compressed_size = lzf::compress(sw.data.data() + 1, sw.data.size() - 1, buffer + 2, sizeof(buffer) - 2);
			compressed_size != 0 && (compressed_size + 2) < sw.data.size()
			)
		{
			buffer[0] = (decompressed_size >> 6) | 0x80;
			buffer[1] = (decompressed_size & 0x3F) | 0xC0;
			return std::string((const char*)buffer, compressed_size + 2);
		}
	}
#endif

	SOUP_MOVE_RETURN(sw.data);
}

static bool is_u35_or_below(const std::string_view& salt)
{
	return salt == "b471e49539930dc9b5a131e6247c7387F"
		|| is_u32_or_below(salt)
		;
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
	std::string_view salt;
	native_u32_t reflexive_ip;
	native_u32_t local_ip;

	native_u16_t reflexive_port_client = 4955;
	native_u16_t reflexive_port_server = 4950;
	//native_u16_t local_port_client = 4955;
	native_u16_t local_port_server = 4950;

	uint8_t status;
	std::string presence;

	time_t last_nat_bind;

	void sendGameInvite(Socket& s, const std::string& inviter_acctId, const std::string& invitee_acctId, const std::string& session_info, const std::string& inviter_name, uint8_t unk = 0, uint8_t presence_mode = 3)
	{
		StringWriter sw;
		{ uint8_t b = 0x7c; sw.u8(b); }
		sw.str(12, inviter_acctId);
		sw.u8(unk);
		sw.str(12, invitee_acctId);
		sw.u8(presence_mode);
		ser_str(sw, this->salt, const_cast<std::string&>(session_info));
		ser_str(sw, this->salt, const_cast<std::string&>(inviter_name));
		std::string unk_str; ser_str(sw, this->salt, unk_str);
		s.udpServerSend(SocketAddr(this->reflexive_ip, this->reflexive_port_client), packData(sw.data, this->salt));
	}
};
static std::unordered_map<std::string, AccountData> account_map;

int main(int argc, const char** argv)
{
	Server serv;

	ServerServiceUdp srv([](Socket& s, SocketAddr&& addr, std::string&& data, ServerServiceUdp&)
	{
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
				//return;
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
								salt = "b471e49539930dc9b5a131e6247c7387A"; // < U23
								if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
								{
									std::cout << addr.toString() << " - Checksum mismatch" << std::endl;
									return;
								}
							}
						}
					}
				}
			}
		}
		//std::cout << addr.toString() << " - salt = " << salt << std::endl;

		uint8_t packet_id;
		sr.u8(packet_id);
		switch (packet_id)
		{
		case 0x54: // Test from client
		case 0x74: // Test from server
			{
				std::string acctId;
				sr.str(12, acctId);
				uint64_t timestamp;
				if (!is_u27_or_below(salt))
				{
					sr.u64_le(timestamp);
				}
				uint32_t local_ip;
				sr.u32_be(local_ip);
				uint16_t local_port;
				sr.u16_le(local_port);
				std::string local_addr_str;
				ser_str(sr, salt, local_addr_str);

				//std::cout << addr.toString() << " - local_addr: " << IpAddr((native_u32_t)local_ip).toString() << ":" << local_port << std::endl;
				//std::cout << addr.toString() << " - local_addr_str: " << local_addr_str << std::endl;

				uint32_t reflexive_ip = addr.ip.getV4NativeEndian();
				uint16_t reflexive_port = addr.getPort();

				reflexive_ip ^= 0xAAAAAAAA;
				reflexive_port ^= 0xAAAA;

				StringWriter sw;
				{ uint8_t b = 0x64; sw.u8(b); }
				{ uint8_t b = 0; sw.u8(b); }
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
				s.udpServerSend(addr, packData(sw.data, salt));
			}
			break;

		case 0x42: // NAT bind for client
		case 0x62: // NAT bind for server
			{
				std::string acctId;
				sr.str(12, acctId);
				uint32_t local_ip;
				sr.u32_be(local_ip);
				uint16_t local_port;
				sr.u16_le(local_port);
				if (!is_u32_or_below(salt))
				{
					sr.skip(2);
				}

				local_ip ^= 0xAAAAAAAA;
				local_port ^= 0xAAAA;

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
				if (packet_id == 0x42)
				{
					data->reflexive_port_client = reflexive_port;
					//data->local_port_client = local_port;
					sr.u8(data->status);
					sr.skip(1);
					ser_str(sr, salt, data->presence);

					//std::cout << addr.toString() << " - " << string::bin2hex(acctId) << " - NAT bound for client " << string::bin2hex(acctId) << std::endl;
					//std::cout << addr.toString() << " - " << string::bin2hex(acctId) << " - Client Local Addr: " << IpAddr((native_u32_t)local_ip).toString() << ":" << local_port << std::endl;
					//std::cout << addr.toString() << " - " << string::bin2hex(acctId) << " - Status: " << (int)data->status << std::endl;
					//std::cout << addr.toString() << " - " << string::bin2hex(acctId) << " - Presence: " << data->presence << std::endl;

					//data->sendGameInvite(s, acctId, acctId, R"({})", "Welcome :)", 0, 0);
				}
				else
				{
					//std::cout << addr.toString() << " - " << string::bin2hex(acctId) << " - Server Local Addr: " << IpAddr((native_u32_t)local_ip).toString() << ":" << local_port << std::endl;

					data->reflexive_port_server = reflexive_port;
					data->local_port_server = local_port;
				}
				data->last_nat_bind = time::unixSeconds();

				reflexive_ip ^= 0xAAAAAAAA;
				reflexive_port ^= 0xAAAA;

				StringWriter sw;
				{ uint8_t b = 0x60; sw.u8(b); }
				{ uint8_t b = 0; sw.u8(b); } // should be 1 if we supported proxying?
				if (!is_u32_or_below(salt))
				{
					{ uint8_t b = (packet_id == 0x42 ? 1 : 0); sw.u8(b); }
				}
				sw.u32_be(reflexive_ip);
				sw.u16_le(reflexive_port);
				s.udpServerSend(addr, packData(sw.data, salt));
			}
			break;

		case 0x55: // Logout
			{
				std::string acctId;
				sr.str(12, acctId);
				account_map.erase(acctId);
			}
			break;

		case 0x70: // Fast presence query
		case 0x50: // Rich presence query
			{
				std::string acctId;
				sr.str(12, acctId);
				uint8_t task_id;
				sr.u8(task_id);
				uint8_t num_queries = 0;
				sr.u8(num_queries);

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
						if (time::unixSecondsSince(e->second.last_nat_bind) <= 120)
						{
							sw.u8(e->second.status);
							if (packet_id == 0x50)
							{
								ser_str(sw, salt, e->second.presence);
							}
							continue;
						}
						account_map.erase(e);
					}
					{ uint8_t b = 0; sw.u8(b); }
					if (packet_id == 0x50)
					{
						std::string str;
						ser_str(sw, salt, str);
					}
				}
				s.udpServerSend(addr, packData(sw.data, salt));
			}
			break;

		case 0x72: // Query account server address
			{
				std::string acctId;
				sr.str(12, acctId);
				uint8_t task_id;
				sr.u8(task_id);
				sr.skip(1);
				std::string query;
				sr.str(12, query);
				if (auto e = account_map.find(query); e != account_map.end())
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
						uint32_t masked_ip = e->second.reflexive_ip ^ 0xAAAAAAAA;
						sw.u32_be(masked_ip);
					}
					{
						uint16_t masked_port = e->second.reflexive_port_server ^ 0xAAAA;
						sw.u16_le(masked_port);
					}
					{
						uint32_t masked_ip = e->second.local_ip ^ 0xAAAAAAAA;
						sw.u32_be(masked_ip);
					}
					{
						uint16_t masked_port = e->second.local_port_server ^ 0xAAAA;
						sw.u16_le(masked_port);
					}
					s.udpServerSend(addr, packData(sw.data, salt));
				}
			}
			break;

		case 0x63: // Introduction request
		case 0x69: // Relayed introduction request
			{
				std::string acctId;
				sr.str(12, acctId);
				uint8_t task_id;
				sr.u8(task_id);
				std::string target;
				sr.str(12, target);
				if (auto e = account_map.find(target); e != account_map.end())
				{
					uint32_t reflexive_ip = addr.ip.getV4NativeEndian();
					uint16_t reflexive_port = addr.getPort();

					reflexive_ip ^= 0xAAAAAAAA;
					reflexive_port ^= 0xAAAA;

					StringWriter sw;
					{ uint8_t b = 0x70; sw.u8(b); }
					sw.u8(task_id);
					{ uint8_t b = 0; sw.u8(b); }
					sw.str(12, acctId);
					sw.str(12, target);
					sw.u32_be(reflexive_ip);
					sw.u16_le(reflexive_port);
					s.udpServerSend(SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_server), packData(sw.data, e->second.salt));
				}
			}
			break;

		case 0x76: // Game invite
		case 0x79: // Relayed game invite
			{
				std::string acctId;
				sr.str(12, acctId);
				uint8_t unk;
				sr.u8(unk);
				std::string target;
				sr.str(12, target);
				uint8_t presence_mode;
				sr.u8(presence_mode);
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
					e->second.sendGameInvite(s, acctId, target, session_info, inviter_name, unk, presence_mode);
				}
				else
				{
					// Send game invite response with status 0 for offline
					StringWriter sw;
					{ uint8_t b = 0xa4; sw.u8(b); }
					sw.str(12, acctId);
					sw.str(12, target);
					uint8_t status = 0;
					sw.u8(status);
					s.udpServerSend(addr, packData(sw.data, salt));
				}
			}
			break;

		case 0x56: // Game invite response
			{
				std::string acctId;
				sr.str(12, acctId);
				std::string target;
				sr.str(12, target);
				uint8_t status; // 1 = received. 3 = declined. 4 = failed to join.
				sr.u8(status);
				if (auto e = account_map.find(target); e != account_map.end())
				{
					StringWriter sw;
					{ uint8_t b = 0xa4; sw.u8(b); }
					sw.str(12, target);
					sw.str(12, acctId);
					sw.u8(status);
					s.udpServerSend(SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_server), packData(sw.data, e->second.salt));
				}
			}
			break;

		case 0x6a: // Send social change (when accepting a friend request or removing a friend in U39 and below; done via IRC nowadays)
			{
				std::string acctId; sr.str(12, acctId);
				uint8_t task_id; sr.u8(task_id);
				uint8_t num_changes = 0; sr.u8(num_changes);
				while (num_changes--)
				{
					std::string target; sr.str(12, target);
					std::string json; ser_str(sr, salt, json);
					if (auto e = account_map.find(target); e != account_map.end())
					{
						StringWriter sw;
						{ uint8_t b = 0xac; sw.u8(b); }
						sw.u8(task_id);
						ser_str(sw, e->second.salt, json);
						s.udpServerSend(SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_client), packData(sw.data, e->second.salt));
					}
				}
			}
			break;

		case 0x73: // Request friend refresh (when sending a friend request in U39 and below; done via IRC nowadays)
			{
				std::string acctId; sr.str(12, acctId);
				uint8_t unk; sr.u8(unk); // always 0x09 ?
				uint8_t num_targets = 0; sr.u8(num_targets);
				while (num_targets--)
				{
					std::string target; sr.str(12, target);
					if (auto e = account_map.find(target); e != account_map.end())
					{
						StringWriter sw;
						{ uint8_t b = 0x78; sw.u8(b); }
						sw.u8(unk);
						s.udpServerSend(SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_client), packData(sw.data, e->second.salt));
					}
				}
			}
			break;

		default:
			std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			break;
		}
	});

	if (!serv.bindUdp(1234, &srv))
	{
		std::cout << "Failed to bind UDP/1234" << std::endl;
		return 1;
	}
	std::cout << "Bound to UDP/1234" << std::endl;

#ifdef DOCKER
	// Ctrl+C not killing your software? According to the professional ChatGPTs hired by Docker Inc, it's not an issue. Why? Because there's a workaround!
	signal(SIGTERM, [](int) { exit(0); });
#endif

	serv.run();
}
