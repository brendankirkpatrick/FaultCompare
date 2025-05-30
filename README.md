# FaultCompare
Runs a comparison/analysis between [FaultArm](https://github.com/brendankirkpatrick/FaultArm)(fork of [UC FaultArm](https://github.com/UCdasec/FaultArm)) and
[FaultFlipper](https://github.com/UCdasec/FaultFlipper) projects. Note that FaultFlipper is currently private, so you will need to be granted access to the repo to clone its submodule.

Each respective project is added as a [submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules). To clone, users should make sure they have access to each submodule repo, and then run
```bash
git clone git@github.com:brendankirkpatrick/FaultCompare.git FaultCompare/
git submodule update --init --recursive
```

## Requirements:
The project provides a Dockerfile that you can use to create an image from to run. To find out more on how to install Docker, [click here](https://docs.docker.com/engine/install/).
To run the program in docker, create an image and run it (to run without sudo you must be a part of the docker users group):
```bash
cd FaultCompare
docker build -t fault-compare .
docker run --rm fault-compare
```

Alternatively, the project uses [pixi](https://github.com/prefix-dev/pixi) for dependency management. To run natively, you can install pixi with:
```bash
curl -fsSL https://pixi.sh/install.sh | bash
```
Next, you need to make sure you have the appropriate ARM emulation tools installed with:
```bash
sudo apt install gcc-arm-linux-gnueabi
sudo apt install qemu-user-static
```
You can then install Python dependencies and run the project with:
```bash
pixi install
pixi run compare
```

## Usage:
You can either run the project via the *Dockerfile* or via `pixi run compare` (see setup above).

To run the project via the pixi file, you must first enter a *pixi shell environment*.\
Then, you can simply run the Python code like any ordinary Python script:
```bash 
pixi shell
python src/compare.py --binary test_files/pass_bin
```

To run the project via a Docker container, you must first build your docker image.\
You can either launch with the default command (specified in the Dockerfile), or you can provide your own command:
```bash 
# Run with the "default" command
docker run --rm fault-compare
# Run with custom flags
docker run --rm fault-compare python src/compare.py --binary test_files/pass_bin
# You can also enter the docker container environment to run manually
# (use ulimit to disable core dumps)
docker run --rm --ulimit core=0 -it fault-compare bash
```

To read more about the default options, run the program with the `--help` flag.
```bash 
python src/compare.py --help
```
