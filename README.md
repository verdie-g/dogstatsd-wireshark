# dogstatsd-wireshark
Wireshark Dissector for [DogStatsD](https://docs.datadoghq.com/developers/dogstatsd).

![dogstatsd-dissector](https://user-images.githubusercontent.com/9092290/82764408-bf092600-9e0e-11ea-8924-551b0680ceef.png)

## Installation

```bash
sudo wget https://raw.githubusercontent.com/verdie-g/dogstatsd-wireshark/master/dogstatsd.lua -P /usr/lib/x86_64-linux-gnu/wireshark/plugins
```

Check your plugins path in Wireshark > Help > About Wireshark > Folders.
