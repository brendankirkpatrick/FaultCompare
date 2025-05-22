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
In the pixi file I have preset the following command:
```bash 
python src/compare.py --binary test_files/pass_bin
```
You can either run the project via the *Dockerfile* or via `pixi run compare`.
Alternatively, to change the command that is run, you can change the binary file in the *pixi.toml* file to an arm32 binary.

