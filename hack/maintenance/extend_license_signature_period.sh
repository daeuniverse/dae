#!/bin/bash

rg -F 'Copyright (c) 2022-2024' --files-with-matches . | xargs sed -i 's/Copyright (c) 2022-2025/Copyright (c) 2022-2025'/g
rg -F 'Copyright (c) 2024' --files-with-matches . | xargs sed -i 's/Copyright (c) 2022-2025/Copyright (c) 2022-2025'/g
