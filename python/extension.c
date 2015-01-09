/*
Twopence python bindings

Copyright (C) 2014 SUSE

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


#include <Python.h>
#include <fcntl.h>
#include "twopence.h"

typedef struct {
	PyObject_HEAD

	struct twopence_target *handle;
} twopence_Target;

typedef struct {
	PyObject_HEAD

	char *		command;
	char *		user;
	char *		stdinPath;
	PyObject *	stdout;
	PyObject *	stderr;

	twopence_buffer_t stdoutBuffer;
	twopence_buffer_t stderrBuffer;
} twopence_Command;

static void		Target_dealloc(twopence_Target *self);
static PyObject *	Target_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static int		Target_init(twopence_Target *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_run(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_inject(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_extract(PyObject *self, PyObject *args, PyObject *kwds);
static void		Command_dealloc(twopence_Command *self);
static PyObject *	Command_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static int		Command_init(twopence_Command *self, PyObject *args, PyObject *kwds);
static PyObject *	Command_stdout(twopence_Command *);
static int		Command_Check(PyObject *);
static int		Command_build(twopence_Command *, twopence_command_t *);

static inline void
drop_string(char **strp)
{
	if (*strp)
		free(*strp);
	*strp = NULL;
}

static inline void
drop_object(PyObject **objp)
{
	if (*objp) {
		Py_DECREF(*objp);
	}
	*objp = NULL;
}

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

static PyTypeObject twopence_TargetType = {
	PyObject_HEAD_INIT(NULL)

	.tp_name	= "twopence.Target",
	.tp_basicsize	= sizeof(twopence_Target),
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "Twopence target",

	.tp_methods	= twopence_targetMethods,
	.tp_init	= (initproc) Target_init,
	.tp_new		= Target_new,
	.tp_dealloc	= (destructor) Target_dealloc,
};

/*
 * Define the python bindings of class "Command"
 *
 * Create objects using
 *   command = twopence.Command("/bin/ls");
 *
 * Or like this:
 *   out = bytearray()
 *   err = bytearray()
 *   cmd = twopence.Command("/bin/ls", stdout = out, stderr = err, user = "okir")
 *
 * Supported keyword arguments in the constructor:
 *   user
 *	The user to run this command as; default is "root"
 *   stdin
 *	The file to pass to the command's standard input. Right now,
 *	this only accepts a string specifying a path name. File or buffer
 *	objects are not supported yet.
 *   stdout, stderr:
 *	Buffers to write the respective output streams to.
 *	If not specified, output is written to the python interpreter's stdout.
 *	Pass the None object to suppress output.
 *	If you just specify stdout but not stderr, the two output streams
 *	are combined into one and buffered together.
 *
 * To run this command on the SUT, use
 *   target.run(cmd)
 */
static PyMethodDef twopence_commandMethods[] = {
      {	"stdout", (PyCFunction) Command_stdout, METH_NOARGS,
	"Return the stdout buffer for this command"
      },
      {	NULL }
};

static PyTypeObject twopence_CommandType = {
	PyObject_HEAD_INIT(NULL)

	.tp_name	= "twopence.Command",
	.tp_basicsize	= sizeof(twopence_Command),
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "Twopence command",

	.tp_methods	= twopence_commandMethods,
	.tp_init	= (initproc) Command_init,
	.tp_new		= Command_new,
	.tp_dealloc	= (destructor) Command_dealloc,
};

/*
 * Methods belonging to the module itself.
 * None so far
 */
static PyMethodDef twopence_methods[] = {
      {	NULL }
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
# define PyMODINIT_FUNC void
#endif

/*
 * Convert twopence error to an exception
 */
static PyObject *
twopence_Exception(const char *msg, int rc)
{
	char buffer[256];

	snprintf(buffer, sizeof(buffer), "%s: %s", msg, twopence_strerror(rc));
	PyErr_SetString(PyExc_SystemError, buffer);
	return NULL;
}

/*
 * Constructor: allocate empty Command object, and set its members.
 */
static PyObject *
Command_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	twopence_Command *self;

	self = (twopence_Command *) type->tp_alloc(type, 0);
	if (self == NULL)
		return NULL;

	/* init members */
	self->command = NULL;
	self->user = NULL;
	self->stdinPath = NULL;
	self->stdout = NULL;
	self->stderr = NULL;

	twopence_buffer_init(&self->stdoutBuffer);
	twopence_buffer_init(&self->stderrBuffer);

	return (PyObject *)self;
}

/*
 * Initialize the command object
 *
 * Typical ways to do this include
 *    cmd = twopence.Command("/bin/ls", user = "okir", stdout = bytearray());
 *    cmd = twopence.Command("/bin/ls", user = "okir", stdout = str());
 *    cmd = twopence.Command("/usr/bin/wc", stdin = "/etc/hosts");
 */
static int
Command_init(twopence_Command *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"command",
		"user",
		"stdin",
		"stdout",
		"stderr",
		NULL
	};
	PyObject *stdinObject = NULL, *stdoutObject = NULL, *stderrObject = NULL;
	char *command, *user = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|sOOO", kwlist, &command, &user, &stdinObject, &stdoutObject, &stderrObject))
		return -1;

	self->command = strdup(command);
	self->user = user? strdup(user) : NULL;

	if (stdoutObject) {
		Py_INCREF(stdoutObject);
		self->stdout = stdoutObject;
	}
	if (stderrObject) {
		Py_INCREF(stderrObject);
		self->stderr = stderrObject;
	}
	if (stdinObject && stdinObject != Py_None) {
		char *s;

		if ((s = PyString_AsString(stdinObject)) == NULL)
			return -1;
		self->stdinPath = strdup(s);
	}

	return 0;
}

/*
 * Destructor: clean any state inside the Command object
 */
static void
Command_dealloc(twopence_Command *self)
{
	drop_string(&self->command);
	drop_string(&self->user);
	drop_string(&self->stdinPath);
	drop_object(&self->stdout);
	drop_object(&self->stderr);

	twopence_buffer_free(&self->stdoutBuffer);
	twopence_buffer_free(&self->stderrBuffer);
}

static int
Command_Check(PyObject *self)
{
	return PyType_IsSubtype(Py_TYPE(self), &twopence_CommandType);
}

static int
Command_build(twopence_Command *self, twopence_command_t *cmd)
{
	twopence_command_init(cmd, self->command);

	cmd->user = self->user;

	twopence_command_ostreams_reset(cmd);
	if (self->stdout == NULL && self->stderr == NULL) {
		twopence_command_ostream_redirect(cmd, TWOPENCE_STDOUT, 1);
		twopence_command_ostream_redirect(cmd, TWOPENCE_STDERR, 2);
	} else
	if (self->stdout == Py_None && self->stderr == Py_None) {
		/* ostreams have already been reset above */
	} else {
		if (self->stderr == NULL) {
			/* Capture both stdout and stderr into one buffer */
			twopence_command_alloc_buffer(cmd, TWOPENCE_STDOUT, 65536);
			twopence_command_ostream_capture(cmd, TWOPENCE_STDOUT, &cmd->stdout_buf);
			twopence_command_ostream_capture(cmd, TWOPENCE_STDERR, &cmd->stdout_buf);
		} else {
			/* Capture stdout and stderr separately */
			twopence_command_alloc_buffer(cmd, TWOPENCE_STDOUT, 65536);
			twopence_command_alloc_buffer(cmd, TWOPENCE_STDERR, 65536);

			twopence_command_ostream_capture(cmd, TWOPENCE_STDOUT, &cmd->stdout_buf);
			twopence_command_ostream_capture(cmd, TWOPENCE_STDERR, &cmd->stderr_buf);
		}
	}

	if (self->stdinPath != NULL) {
		int fd = open(self->stdinPath, O_RDONLY);

		twopence_source_init_fd(&cmd->source, fd);
	}

	return 0;
}

static PyObject *
Command_stdout(twopence_Command *self)
{
	PyObject *result;

	result = self->stdout;
	if (result == NULL)
		result = Py_None;
	Py_INCREF(result);
	return result;
}

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

	return (PyObject *)self;
}

static int
Target_init(twopence_Target *self, PyObject *args, PyObject *kwds)
{
	char *targetSpec;
	int rc;

	static char *kwlist[] = {"target", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &targetSpec))
		return -1; 

	rc = twopence_target_new(targetSpec, &self->handle);
	if (rc < 0) {
		twopence_Exception("Target initialization", rc);
		return -1;
	}

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

/*
 * The run() method can return data in buffers
 * Support this here.
 */
int
twopence_AppendBuffer(PyObject *buffer, const twopence_buffer_t *buf)
{
	int rv = 0;

	if (buffer != NULL && buffer != Py_None && buf->head != NULL) {
		PyObject *temp = PyString_FromString(buf->head);

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
		cmdObject = PyObject_New(twopence_Command, &twopence_CommandType);

		if (Command_init(cmdObject, args, kwds) < 0)
			goto out;
	}

	if ((handle = Target_handle(self)) == NULL)
		goto out;

	if (Command_build(cmdObject, &cmd) < 0)
		goto out;

	printf("run \"%s\" as user %s\n", cmd.command, cmd.user);
	rc = twopence_run_test(handle, &cmd, &status);
	if (rc < 0) {
		twopence_Exception("run", rc);
		goto out;
	}

	/* Now funnel the captured data to the respective buffer objects */
	if (twopence_AppendBuffer(cmdObject->stdout, &cmd.stdout_buf) < 0)
		goto out;
	if (twopence_AppendBuffer(cmdObject->stderr, &cmd.stderr_buf) < 0)
		goto out;

	result = PyInt_FromLong(status.minor);

out:
	if (cmdObject) {
		Py_DECREF(cmdObject);
	}

	/* Should this be in twopence_command_destroy? */
	if (cmd.source.fd >= 0)
		close(cmd.source.fd);

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

static void
registerType(PyObject *m, const char *name, PyTypeObject *type)
{
	type->tp_new = PyType_GenericNew;
	if (PyType_Ready(type) < 0)
		return;

	Py_INCREF(type);
	PyModule_AddObject(m, name, (PyObject *) type);
}

PyMODINIT_FUNC
inittwopence(void) 
{
	PyObject* m;

	m = Py_InitModule3("twopence", twopence_methods, "Module for twopence based testing");

	registerType(m, "Target", &twopence_TargetType);
	registerType(m, "Command", &twopence_CommandType);
}
