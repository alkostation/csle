# OS
FROM kthnse/csle_flat_ubuntu_22_base:0.7.0
USER root

ENV DEBIAN_FRONTEND=noninteractive

# Install packages
RUN set -eux; \
	apt-get update && \
    apt install -y ffmpeg bash \
    gstreamer1.0-tools \
    gstreamer1.0-plugins-base \
    gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad \
    gstreamer1.0-plugins-ugly \
    gstreamer1.0-libav \
    libgstrtspserver-1.0-dev \
    python3-gi \
    python3-gst-1.0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy the resource files with the correct permissions
COPY ./docker_files/rtsp_cam_base/docker/res/Office_Door_1280x720d.mp4  /root/
COPY ./docker_files/rtsp_cam_base/docker/res/server.py  /root/


# Copy the entrypoint script
COPY ./docker_files/rtsp_cam_base/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Set the proper permissions and ownership
RUN set -eux; \
    chmod +x /usr/local/bin/docker-entrypoint.sh


# Set the entry point
# CMD ["python", "/root/server.py"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Port 8554 TCP+UDP
EXPOSE 8554


