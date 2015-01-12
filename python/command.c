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

static void		Command_dealloc(twopence_Command *self);
static PyObject *	Command_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static PyObject *	Command_getattr(twopence_Command *self, char *name);
static int		Command_setattr(twopence_Command *self, char *name, PyObject *);
static PyObject *	Command_suppressOutput(twopence_Command *, PyObject *, PyObject *);

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
      {	"suppressOutput", (PyCFunction) Command_suppressOutput, METH_VARARGS | METH_KEYWORDS,
	"Do not display command's output to screen"
      },
      {	NULL }
};

PyTypeObject twopence_CommandType = {
	PyObject_HEAD_INIT(NULL)

	.tp_name	= "twopence.Command",
	.tp_basicsize	= sizeof(twopence_Command),
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "Twopence command",

	.tp_methods	= twopence_commandMethods,
	.tp_init	= (initproc) Command_init,
	.tp_new		= Command_new,
	.tp_dealloc	= (destructor) Command_dealloc,

	.tp_getattr	= (getattrfunc) Command_getattr,
	.tp_setattr	= (setattrfunc) Command_setattr,
};

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
	self->suppressOutput = 0;

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
int
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
	self->stdout = NULL;
	self->stderr = NULL;
	self->stdinPath = NULL;
	self->suppressOutput = 0;

	if (stdoutObject == NULL) {
		stdoutObject = twopence_callType(&PyByteArray_Type, NULL, NULL);
	} else {
		Py_INCREF(stdoutObject);
	}
	self->stdout = stdoutObject;

	if (stderrObject == NULL)
		stderrObject = stdoutObject;

	Py_INCREF(stderrObject);
	self->stderr = stderrObject;

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
}

int
Command_Check(PyObject *self)
{
	return PyType_IsSubtype(Py_TYPE(self), &twopence_CommandType);
}

int
Command_build(twopence_Command *self, twopence_command_t *cmd)
{
	twopence_buffer_t *buffer = NULL;

	twopence_command_init(cmd, self->command);

	cmd->user = self->user;

	twopence_command_ostreams_reset(cmd);
	if (self->suppressOutput || self->stdout == Py_None) {
		/* ostream has already been reset above */
	} else {
		/* Copy remote stdout to our stdout */
		twopence_command_iostream_redirect(cmd, TWOPENCE_STDOUT, 1, false);
	}

	if (self->stdout == NULL || PyByteArray_Check(self->stdout)) {
		/* Capture command output in a buffer */
		buffer = twopence_command_alloc_buffer(cmd, TWOPENCE_STDOUT, 65536);
		twopence_command_ostream_capture(cmd, TWOPENCE_STDOUT, buffer);
	}

	if (self->suppressOutput || self->stderr == Py_None) {
		/* ostream has already been reset above */
	} else {
		/* Copy remote stderr to our stderr */
		twopence_command_iostream_redirect(cmd, TWOPENCE_STDERR, 2, false);
	}

	/* If cmd.stdout and cmd.stderr are both NULL, or both refer to the same
	 * bytearray object, send the remote stdout and stderr to a shared buffer */
	if (buffer != NULL && self->stderr == self->stdout) {
		twopence_command_ostream_capture(cmd, TWOPENCE_STDERR, buffer);
	} else 
	if (self->stderr == NULL || PyByteArray_Check(self->stderr)) {
		buffer = twopence_command_alloc_buffer(cmd, TWOPENCE_STDERR, 65536);
		twopence_command_ostream_capture(cmd, TWOPENCE_STDERR, buffer);
	}

	if (self->stdinPath != NULL) {
		int fd = open(self->stdinPath, O_RDONLY);

		twopence_command_iostream_redirect(cmd, TWOPENCE_STDIN, fd, true);
	}

	return 0;
}

static PyObject *
Command_suppressOutput(twopence_Command *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		NULL
	};
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist))
		return NULL;

	self->suppressOutput = 1;
	Py_INCREF(Py_None);
	return Py_None;
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

static PyObject *
Command_stderr(twopence_Command *self)
{
	PyObject *result;

	result = self->stderr;
	if (result == NULL)
		result = Py_None;
	Py_INCREF(result);
	return result;
}

static PyObject *
Command_getattr(twopence_Command *self, char *name)
{
	if (!strcmp(name, "commandline"))
		return PyString_FromString(self->command);
	if (!strcmp(name, "stdout"))
		return Command_stdout(self);
	if (!strcmp(name, "stderr"))
		return Command_stderr(self);

	return Py_FindMethod(twopence_commandMethods, (PyObject *) self, name);
}

static int
Command_setattr(twopence_Command *self, char *name, PyObject *v)
{
	if (!strcmp(name, "stdout")) {
		if (v != Py_None && !PyByteArray_Check(v))
			goto bad_attr;
		assign_object(&self->stdout, v);
		return 0;
	}
	if (!strcmp(name, "stderr")) {
		if (v != Py_None && !PyByteArray_Check(v))
			goto bad_attr;
		assign_object(&self->stderr, v);
		return 0;
	}

	(void) PyErr_Format(PyExc_AttributeError, "Unknown attribute: %s", name);
	return -1;

bad_attr:
	(void) PyErr_Format(PyExc_AttributeError, "Incompatible value for attribute: %s", name);
	return -1;

}
