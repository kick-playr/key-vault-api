#!/bin/sh
exec node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("base64") + "\n")'
