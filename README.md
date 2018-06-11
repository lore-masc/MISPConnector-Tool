# MISPConnector Tool
![Screenshot](https://github.com/lore-masc/MISPConnector-Tool/blob/master/resources/mispconnector.png)

The jar allows to import an event in MISP platform thanks its confortable GUI. It is conceived to upload vulnerability with few clicks.

### Prerequisites

Before execute the application, you make sure to have setted config file correctly.
If you run program on windows, type the seguent config content.

```
https://misp-url.org
a4PLf8QICdDdOmFjwdtSYqkCqn9CvN0VQt7mpUUf
cmd /C start update_event.exe
```

If you run program on unix bash, type the seguent config content.
```
https://misp-url.org
a4PLf8QICdDdOmFjwdtSYqkCqn9CvN0VQt7mpUUf
python3 update_event.py
```

### Installing

Placed in any folder the following files and dirs. You can find them in *dist* dir.

* *data*
* *lib*
* config.txt
* **MISPConnector Tool.jar**
* update_event.exe
* update_event.py

## Authors

* **Lorenzo Masciullo** - *Initial work* - [lore-masc](https://github.com/lore-masc)

## License

This project is open source. Please, contact me for suggestions and reviews.