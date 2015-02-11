/*
Twopence python bindings

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

static void		Target_dealloc(twopence_Target *self);
static PyObject *	Target_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static int		Target_init(twopence_Target *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_getattr(twopence_Target *self, char *name);
static PyObject *	Target_run(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_property(twopence_Target *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_inject(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_extract(PyObject *self, PyObject *args, PyObject *kwds);

/*
 * Define the python bindings of class "Target"
 *
 * Create objects using
 *   target = twopence.Target("ssh:somehost");
 *
 * Then invoke methods like this:
 *   target.inject("myhostsfile", "/etc/hosts", mode = 0644, user = "root")
 *
 * Note that errors are not indicated through the return value, but through
 * exceptions.
 */
static PyMethodDef twopence_targetMethods[] = {
      {	"property", (PyCFunction) Target_property, METH_VARARGS | METH_KEYWORDS,
	"Obtain property defined by the target config"
      },
      {	"run", (PyCFunction) Target_run, METH_VARARGS | METH_KEYWORDS,
	"Run a command on the SUT"
      },
      {	"inject", (PyCFunction) Target_inject, METH_VARARGS | METH_KEYWORDS,
	"Inject a file to the SUT"
      },
      {	"extract", (PyCFunction) Target_extract, METH_VARARGS | METH_KEYWORDS,
	"Extract a file from the SUT"
      },

      {	NULL }
};

PyTypeObject twopence_TargetType = {
	PyObject_HEAD_INIT(NULL)

	.tp_name	= "twopence.Target",
	.tp_basicsize	= sizeof(twopence_Target),
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "Twopence target",

	.tp_methods	= twopence_targetMethods,
	.tp_init	= (initproc) Target_init,
	.tp_new		= Target_new,
	.tp_dealloc	= (destructor) Target_dealloc,

	.tp_getattr	= (getattrfunc) Target_getattr,
};

/*
 * Constructor: allocate empty Target object, and set its members.
 */
static PyObject *
Target_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	twopence_Target *self;

	self = (twopence_Target *) type->tp_alloc(type, 0);
	if (self == NULL)
		return NULL;

	/* init members */
	self->handle = NULL;
	self->attrs = NULL;
	self->name = NULL;

	return (PyObject *)self;
}

static int
Target_init(twopence_Target *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"target", "attrs", "name", NULL};
	PyObject *attrDict = NULL;
	char *targetSpec, *name = NULL;
	int rc;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|Os", kwlist, &targetSpec, &attrDict, &name))
		return -1; 

	rc = twopence_target_new(targetSpec, &self->handle);
	if (rc < 0) {
		twopence_Exception("Target initialization", rc);
		return -1;
	}

	if (attrDict) {
		self->attrs = attrDict;
		Py_INCREF(attrDict);
	}
	if (name)
		self->name = strdup(name);

	return 0;
}

/*
 * Destructor: clean any state inside the Target object
 */
static void
Target_dealloc(twopence_Target *self)
{
	if (self->handle)
		twopence_target_free(self->handle);
	self->handle = NULL;

	drop_object(&self->attrs);
}

/*
 * Extract twopence target handle from python object.
 * This should really do a type check and throw an exception if it doesn't match
 */
static struct twopence_target *
Target_handle(PyObject *self)
{
	return ((twopence_Target *) self)->handle;
}

static PyObject *
Target_getattr(twopence_Target *self, char *name)
{
	PyObject *value;

	if (!strcmp(name, "name")) {
		if (self->name == NULL) {
			Py_INCREF(Py_None);
			return Py_None;
		}
		return PyString_FromString(self->name);
	}
	
	if (self->attrs
	 && (value = PyDict_GetItemString(self->attrs, name)) != NULL) {
		Py_INCREF(value);
		return value;
	}

	return Py_FindMethod(twopence_targetMethods, (PyObject *) self, name);
}

/*
 * Another way of obtaining a per-target property.
 * The only difference is how missing properties are handled.
 * If there is no "ipaddr" property defined for the target, then
 * target.property("ipaddr") will return None, while
 * using target.ipaddr with throw an exception.
 */
static PyObject *
Target_property(twopence_Target *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"name", NULL};
	PyObject *value;
	char *name;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &name))
		return NULL;

	if (self->attrs
	 && (value = PyDict_GetItemString(self->attrs, name)) != NULL) {
		Py_INCREF(value);
		return value;
	}

	Py_INCREF(Py_None);
	return Py_None;
}


/*
 * The run() method can return data in buffers
 * Support this here.
 */
int
twopence_AppendBuffer(PyObject *buffer, const twopence_buf_t *buf)
{
	unsigned int count;
	int rv = 0;

	count = twopence_buf_count(buf);
	if (buffer != NULL && buffer != Py_None && count != 0) {
		PyObject *temp = PyString_FromStringAndSize(twopence_buf_head(buf), count);

		if (PySequence_InPlaceConcat(buffer, temp) == NULL)
			rv = -1;
		Py_DECREF(temp);
	}
	return rv;
}

/*
 * Run a command on the SUT
 *
 * By default, this will print stderr and stdout to the screen (ie the client
 * side's stdout).
 *
 * If you want to capture all output for later processing, you can pass one
 * or two string objects as parameters 'stdout' und 'stderr'.
 *
 * To suppress all output, pass "none" objects to 'stdout' und 'stderr'.
 */
static PyObject *
Target_run(PyObject *self, PyObject *args, PyObject *kwds)
{
	struct twopence_target *handle;
	twopence_Command *cmdObject = NULL;
	twopence_Status *statusObject;
	twopence_command_t cmd;
	twopence_status_t status;
	PyObject *result = NULL;
	int rc;

	memset(&cmd, 0, sizeof(cmd));

	if (PySequence_Check(args)
	 && PySequence_Fast_GET_SIZE(args) == 1) {
		/* Single argument can be an object of type Command or a string */
		PyObject *object = PySequence_Fast_GET_ITEM(args, 0);

		if (Command_Check(object)) {
			cmdObject = (twopence_Command *) object;
			Py_INCREF(cmdObject);
		}
	}

	if (cmdObject == NULL) {
		cmdObject = (twopence_Command *) twopence_callType(&twopence_CommandType, args, kwds);
		if (cmdObject == NULL)
			goto out;
	}

	if ((handle = Target_handle(self)) == NULL)
		goto out;

	if (Command_build(cmdObject, &cmd) < 0)
		goto out;

	rc = twopence_run_test(handle, &cmd, &status);
	if (rc < 0) {
		twopence_Exception("run", rc);
		goto out;
	}

	/* Now funnel the captured data to the respective buffer objects */
	if (twopence_AppendBuffer(cmdObject->stdout, &cmd.buffer[TWOPENCE_STDOUT]) < 0)
		goto out;
	if (twopence_AppendBuffer(cmdObject->stderr, &cmd.buffer[TWOPENCE_STDERR]) < 0)
		goto out;

	statusObject = (twopence_Status *) twopence_callType(&twopence_StatusType, NULL, NULL);
	statusObject->remoteStatus = status.minor;
	if (cmdObject->stdout) {
		statusObject->stdout = cmdObject->stdout;
		Py_INCREF(statusObject->stdout);
	}
	if (cmdObject->stderr) {
		statusObject->stderr = cmdObject->stderr;
		Py_INCREF(statusObject->stderr);
	}

	result = (PyObject *) statusObject;

out:
	if (cmdObject) {
		Py_DECREF(cmdObject);
	}

	twopence_command_destroy(&cmd);
	return result;
}

/*
 * inject file into SUT
 */
static PyObject *
Target_inject(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"local",
		"remote",
		"user",
		"mode",
		NULL
	};
	struct twopence_target *handle;
	char *sourceFile, *destFile;
	char *user = "root";
	int omode = 0644;
	int rc, remoteRc;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "ss|si", kwlist, &sourceFile, &destFile, &user, &omode))
		return NULL;

	printf("inject %s -> %s (user %s, mode 0%o)\n", sourceFile, destFile, user, omode);

	if ((handle = Target_handle(self)) == NULL)
		return NULL;

	rc = twopence_inject_file(handle, user, sourceFile, destFile, &remoteRc, 0);
	if (rc < 0)
		return twopence_Exception("inject", rc);

	Py_INCREF(Py_None);
	return Py_None;
}

/*
 * extract file from SUT
 */
static PyObject *
Target_extract(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"local",
		"remote",
		"user",
		"mode",
		NULL
	};
	struct twopence_target *handle;
	char *sourceFile, *destFile;
	char *user = "root";
	int omode = 0644;
	int rc, remoteRc;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "ss|si", kwlist, &sourceFile, &destFile, &user, &omode))
		return NULL;

	printf("extract %s -> %s (user %s, mode 0%o)\n", sourceFile, destFile, user, omode);
	if ((handle = Target_handle(self)) == NULL)
		return NULL;

	rc = twopence_extract_file(handle, user, sourceFile, destFile, &remoteRc, 0);
	if (rc < 0)
		return twopence_Exception("extract", rc);

	Py_INCREF(Py_None);
	return Py_None;
}
