FROM ghcr.io/calamity-inc/soup:46af10e1c23bf5d924892e1af02c744eb5abf121

COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++20 -lstdc++ -fno-rtti -O3

ENTRYPOINT ["./a.out"]
