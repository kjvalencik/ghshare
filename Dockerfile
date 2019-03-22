FROM rust:latest

ENV RUSTFLAGS="-Ctarget-feature=+aes,+ssse3"
ENV TARGET=x86_64-unknown-linux-musl

ENV OPENSSL_STATIC=1
ENV OPENSSL_DIR=/opt/openssl-musl

ENV SODIUM_STATIC=1
ENV PKG_CONFIG_ALLOW_CROSS=1
ENV PKG_CONFIG_PATH=/opt/libsodium-musl/lib/pkgconfig

RUN rustup target add $TARGET

RUN apt-get update && apt-get install -y musl-tools

RUN cd /tmp \
    && curl https://www.openssl.org/source/openssl-1.0.2o.tar.gz | tar xzf - \
    && cd openssl-1.0.2o \
    && CC=musl-gcc ./Configure --prefix=/opt/openssl-musl no-dso no-ssl2 no-ssl3 linux-x86_64 -fPIC \
    && make -j$(nproc) \
    && make install

RUN cd /tmp \
    && curl https://download.libsodium.org/libsodium/releases/libsodium-1.0.17.tar.gz | tar xzf - \
    && cd libsodium-1.0.17 \
    && CC=musl-gcc ./configure --prefix=/opt/libsodium-musl --enable-shared=no \
    && make -j$(nproc) \
    && make install

COPY . /src
WORKDIR /src

RUN  cargo build --release --target $TARGET
