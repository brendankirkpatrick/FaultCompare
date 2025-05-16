#!/bin/bash

# Create docker image
docker build -t fault-compare .

# Run image
docker run --rm fault-compare 
