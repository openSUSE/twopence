typedef struct {
	PyObject_HEAD

	twopence_config_t *config;
} twopence_Config;

extern PyTypeObject	twopence_ConfigType;
