FROM ghcr.io/calamity-inc/soup:a869ef936ee5a1245ba62b6cc731cf515f7dd9f5

COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++20 -lstdc++ -fno-rtti -O3

ENTRYPOINT ["./a.out"]
