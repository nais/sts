#!/usr/bin/env bash
#MISE description="Generate DeepCopy, DeepCopyInto, and DeepCopyObject method implementations"
set -euo pipefail

controller-gen +object paths="./..."
