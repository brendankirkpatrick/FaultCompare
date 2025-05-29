FROM ghcr.io/prefix-dev/pixi:latest AS install

WORKDIR /code
COPY pixi.toml .

RUN apt-get update && apt-get install --no-install-recommends -y \
	qemu-user-static && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

RUN pixi install

# Create the shell-hook bash script to activate the environment
RUN pixi shell-hook > /shell-hook.sh

# extend the shell-hook script to run the command passed to the container
RUN echo 'exec "$@"' >> /shell-hook.sh

FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y \
	gcc-arm-linux-gnueabi && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

COPY --from=install /shell-hook.sh /shell-hook.sh
RUN ulimit -c 0
RUN chmod 777 /shell-hook.sh

COPY --from=install /code/.pixi/envs/default /code/.pixi/envs/default
COPY --from=install /usr/bin/qemu-arm-static /usr/bin/qemu-arm-static

WORKDIR /code

COPY FaultArm/ ./FaultArm
COPY FaultFlipper/ ./FaultFlipper
COPY test_files/ ./test_files
COPY src/ ./src

# set the entrypoint to the shell-hook script (activate the environment and run the command)
# no more pixi needed in the prod container
ENTRYPOINT ["/bin/bash", "/shell-hook.sh"]
CMD ["python", "src/compare.py", "-f", "-r", "--binary", "test_files/pass_bin"]
