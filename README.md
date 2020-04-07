# fappfon-vpn-helper

Daemon that forces FRITZ!App Fon to work over non FRITZ!Box VPNs.

## Usage

```
Daemon that forces FRITZ!App Fon to work over non FRITZ!Box VPNs.

Usage:
  fappfon-vpn-helper [-v|-vv] -q QUEUE -f FBOX
  fappfon-vpn-helper -h | --help
  fappfon-vpn-helper --version

Options:
  -q QUEUE --queue=QUEUE  ID of netfilter_queue to attach.
  -f FBOX --fbox=FBOX     DNS name or IPv4 of FRITZ!Box.
  -v                      Increase verbosity of logging to DEBUG
  -vv                     Increase verbosity of logging to TRACE
  -h --help               Show this help.
  --version               Show version.
```

## License

```
fappfon-vpn-helper - Daemon that forces FRITZ!App Fon to work over non FRITZ!Box VPNs
Copyright (C) 2020  nightvisi0n <dev@jneureuther.de>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

`FRITZ!Box` and `FRITZ!App Fon` are trademarks of AVM Computersysteme Vertriebs GmbH, Berlin, Germany.