/*
Twopence python bindings - class Config

Copyright (C) 2014, 2015 SUSE

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 2.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/


#include "extension.h"

#include <fcntl.h>
#include <sys/wait.h>

#include "twopence.h"

static void		Config_dealloc(twopence_Config *self);
static PyObject *	Config_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static int		Config_init(twopence_Config *self, PyObject *args, PyObject *kwds);
static PyObject *	Config_target(twopence_Config *self, PyObject *args, PyObject *kwds);
static PyObject *	Config_buildAttrs(twopence_target_config_t *tgt);

/*
 * Define the python bindings of class "Config"
 * Normally, you do not create Config objects yourself;
 * Usually, these are created as the return value of Command.run()
 */
static PyMethodDef twopence_ConfigMethods[] = {
      {	"target", (PyCFunction) Config_target, METH_VARARGS | METH_KEYWORDS,
	"Create target with the given nickname(handle)"
      },
      {	NULL }
};

PyTypeObject twopence_ConfigType = {
	PyObject_HEAD_INIT(NULL)

	.tp_name	= "twopence.Config",
	.tp_basicsize	= sizeof(twopence_Config),
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "Twopence config",

	.tp_methods	= twopence_ConfigMethods,
	.tp_init	= (initproc) Config_init,
	.tp_new		= Config_new,
	.tp_dealloc	= (destructor) Config_dealloc,
};

/*
 * Constructor: allocate empty Config object, and set its members.
 */
static PyObject *
Config_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	twopence_Config *self;

	self = (twopence_Config *) type->tp_alloc(type, 0);
	if (self == NULL)
		return NULL;

	/* init members */
	self->config = NULL;

	return (PyObject *)self;
}

/*
 * Initialize the status object
 */
static int
Config_init(twopence_Config *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"file",
		NULL
	};
	char *filename = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|s", kwlist, &filename))
		return -1;

	if (filename == NULL) {
		filename = getenv("TWOPENCE_CONFIG_PATH");
		if (filename == NULL)
			filename = "twopence.conf";
	}

	self->config = twopence_config_read(filename);
	if (self->config == NULL) {
		PyErr_Format(PyExc_SystemError, "Unable to read twopence config from file \"%s\"", filename);
		return -1;
	}

	return 0;
}

/*
 * Destructor: clean any state inside the Config object
 */
static void
Config_dealloc(twopence_Config *self)
{
	if (self->config)
		twopence_config_free(self->config);
	self->config = NULL;
}

int
Config_Check(PyObject *self)
{
	return PyType_IsSubtype(Py_TYPE(self), &twopence_ConfigType);
}

static PyObject *
Config_target(twopence_Config *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"name",
		NULL
	};
	char *name = NULL;
	twopence_target_config_t *target_conf;
	PyObject *result = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &name))
		return NULL;

	target_conf = twopence_config_get_target(self->config, name);
	if (target_conf == NULL) {
		PyErr_Format(PyExc_AttributeError, "Unknown target \"%s\"", name);
	} else {
		const char *target_spec = twopence_target_config_get_spec(target_conf);
		PyObject *args = PyTuple_New(3);
		PyObject *attrs;

		attrs = Config_buildAttrs(target_conf);

		PyTuple_SET_ITEM(args, 0, PyString_FromString(target_spec));
		PyTuple_SET_ITEM(args, 1, attrs);
		PyTuple_SET_ITEM(args, 2, PyString_FromString(name));
		Py_INCREF(attrs);

		result = twopence_callType(&twopence_TargetType, args, NULL);

		Py_DECREF(args);
		Py_DECREF(attrs);
	}

	return result;
}

PyObject *
Config_buildAttrs(twopence_target_config_t *tgt)
{
	PyObject *dict;
	const char **names;
	unsigned int i;
	
	names = twopence_target_config_attr_names(tgt);
	if (names == NULL)
		return NULL;

	dict = PyDict_New();
	for (i = 0; names[i]; ++i) {
		const char *value;

		value = twopence_target_config_get_attr(tgt, names[i]);
		if (value != NULL)
			PyDict_SetItemString(dict, names[i], PyString_FromString(value));
	}
	return dict;
}
