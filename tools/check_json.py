#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2023 Intel Corporation

import argparse
import json

"""
Check that a given jsonc configuration file validates against the CNDP schema.
This script requires the "jsonc-parser" and "jsonschema" python packages.
"""

try:
    import jsonc_parser.errors
    import jsonc_parser.parser
except ModuleNotFoundError as e:
    print('Error: {}. Try `pip install jsonc-parser`'.format(e))
    raise SystemExit(1)

try:
    import jsonschema
except ModuleNotFoundError as e:
    print('Error: {}. Try `pip install jsonschema`'.format(e))
    raise SystemExit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser('jsonc file checker',
                formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('jsonc_file', help='The jsonc file to check')
    parser.add_argument('--schema', help='The schema to check against',
                        default='tools/cndp.schema')
    args = parser.parse_args()

    # Convert jsonc to json
    try:
        j = jsonc_parser.parser.JsoncParser.parse_file(args.jsonc_file)
    except jsonc_parser.errors.ParserError as e:
        print('Error:', e)
        raise SystemExit(1)

    # Load schema (as json)
    try:
        with open(args.schema, 'r') as f:
            s = json.load(f)
    except FileNotFoundError as e:
        print('Error:', e)
        raise SystemExit(1)
    except json.decoder.JSONDecodeError as e:
        print('Error: {}:'.format(args.schema), e)
        raise SystemExit(1)

    # Validate json instance against the schema
    try:
        jsonschema.validate(instance=j, schema=s)
    except jsonschema.exceptions.ValidationError as e:
        print('Error:', e)
        raise SystemExit(1)

    print('Success')
