#!/bin/bash

rg -F 'Copyright (c) 2022-2023' --files-with-matches . | xargs sed -i 's/Copyright (c) 2022-2023/Copyright (c) 2022-2024'/g
rg -F 'Copyright (c) 2023' --files-with-matches . | xargs sed -i 's/Copyright (c) 2022-2023/Copyright (c) 2022-2024'/g
