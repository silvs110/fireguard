<div align="center">
    <h1 align="center">fireguard</h1>
    <p align="center">
    A Packet-Filtering Firewall that blocks incoming packets based on IPv4 address.
    <br />
    <a href="https://github.com/silvs110/fireguard/issues/new?assignees=+&labels=bug&template=bug_report.md&title=+">Report Bug</a>
    ·
    <a href="https://github.com/silvs110/fireguard/issues/new?assignees=+&labels=+&template=feature_or_enhancement_request.md&title=+">Request Feature</a>
    </p>

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]

</div>


<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li><a href="#prerequisites">Prerequisites</a></li>
    <li><a href="#installation">Installation</a></li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#disclaimer">Disclaimer</a></li>
  </ol>
</details>

## About The Project
A Packet-Filtering Firewall that blocks incoming packets based on IPv4 address.

## Prerequisites
1. C
2. Linux (Ubuntu 14.04)

## Installation


1. `make`
2. `sudo insmod fireguard.ko`
3. `gcc -o firecontrol ./firecontrol.c`

## Usage
To interact with the firewall run `./firecontrol`. The following commands are supported:
* View Blocked IPs
* Add IP
* Delete IP
<!-- LICENSE -->
## License

TBD

## Disclaimer

This product does not come with a warranty. It is build as part of research project. It should be safe
to run on your system, but we make no claims regarding functionality.

[contributors-shield]: https://img.shields.io/github/contributors/silvs110/fireguard.svg?style=for-the-badge
[contributors-url]: https://github.com/silvs110/fireguard/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/silvs110/fireguard.svg?style=for-the-badge
[forks-url]: https://github.com/silvs110/fireguard/network/members
[stars-shield]: https://img.shields.io/github/stars/silvs110/fireguard.svg?style=for-the-badge
[stars-url]: https://github.com/silvs110/fireguard/stargazers
[issues-shield]: https://img.shields.io/github/issues/silvs110/fireguard.svg?style=for-the-badge
[issues-url]: https://github.com/silvs110/fireguard/issues
[license-shield]: https://img.shields.io/github/license/silvs110/fireguard.svg?style=for-the-badge
[license-url]: https://github.com/silvs110/fireguard/blob/master/LICENSE
