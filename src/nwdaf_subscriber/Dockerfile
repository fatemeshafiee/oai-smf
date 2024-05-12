FROM ubuntu:latest
LABEL authors="aminrezaei"

RUN apt-get update
RUN apt-get install -y build-essential libboost-all-dev  libnghttp2-14
RUN apt-get install -y cmake
RUN apt-get install -y wget
RUN apt-get install -y libssl-dev
RUN apt-get install -y git

ARG make_procs=16
ARG nghttp2_ver=1.51.0
ARG boost_ver=1.84.0

# boost
# This builds boost manually, but we're bypassing this by installing it above

# wget https://sourceforge.net/projects/boost/files/boost/${boost_ver}/boost_$(echo ${boost_ver} | tr '.' '_').tar.gz && tar xvf boost* && cd boost*/ && \

#RUN wget https://boostorg.jfrog.io/artifactory/main/release/${boost_ver}/source/boost_$(echo ${boost_ver} | tr '.' '_').tar.gz && tar xvf boost* && cd boost*/ && \
#    ./bootstrap.sh && ./b2 -j${make_procs} install


# nghttp2
RUN wget https://github.com/nghttp2/nghttp2/releases/download/v${nghttp2_ver}/nghttp2-${nghttp2_ver}.tar.bz2 && tar xf nghttp2* && cd nghttp2*/ && \
    ./configure --enable-asio-lib --disable-shared --enable-python-bindings=no && make -j${make_procs} install

RUN apt-get install -y pkg-config
RUN apt-get install -y vim
RUN apt-get install -y curl

# RUN git clone https://github.com/nlohmann/json.git
# WORKDIR /json
# RUN cmake . -DBUILD_TESTS=OFF
# RUN make install

WORKDIR /srv
COPY . .
RUN ./scripts/build.sh

RUN apt-get update && apt-get install -y openssh-server sudo
RUN useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 2321 test
# RUN  echo 'test:test' | chpasswd
RUN mkdir /var/run/sshd
RUN echo 'root:1111' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
# RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
EXPOSE 22
RUN apt-get install rsync gdb -y

CMD ["/usr/sbin/sshd", "-D"]
# ENTRYPOINT ["/srv/.build/nghttp2_starter"]