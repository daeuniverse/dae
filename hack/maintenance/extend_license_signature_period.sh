#!/bin/bash

rg -F 'Copyright (c) 2022-2026' --files-with-matches . | xargs sed -i 's/Copyright (c) 2022-2026/Copyright (c) 2022-2026'/g
rg -F 'Copyright (c) 2024' --files-with-matches . | xargs sed -i 's/Copyright (c) 2022-2026/Copyright (c) 2022-2026'/g
