# configzone

Configzone is a static configuration extractor implemented in Golang for Warzone RAT (targeting Microsoft Windows). By default the script will print the extracted information to stdout (using the ```-v``` (verbose) flag is recommended for deeper investigations (hexdump, debug information in case of errors). It is also capable of dumping the malware configuration to disk as a JSON file.

## Usage 

```shell
go run configzone.go [-v] [-j] path/to/sample.exe
```
## Screenshots

![Verbose Mode + JSON dump](img/tool.png)

![JSON config file](img/config-json.png)

## Sources/Credits

The idea of this config extractor is based on the work of Sergei Frankoff (OALabs), who covered the [reverse engineering](https://www.youtube.com/watch?v=81fdvmGmRvM) of Warzone RAT and [basic config extraction](https://www.youtube.com/watch?v=-G82xh9m4hc) in a video series on the OALabs Youtube channel.

The analysis write-ups by [Domaintools](https://www.domaintools.com/resources/blog/warzone-1-0-rat-analysis-report) and Yaroslav Harakhavik for [Checkpoint Research](https://research.checkpoint.com/2020/warzone-behind-the-enemy-lines/) were very useful as well.
