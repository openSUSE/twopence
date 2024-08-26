/*
Twopence Python bindings

Copyright (C) 2014-2023 SUSE LLC

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

#include "twopence.h"
#include "utils.h"

static void		Command_dealloc(twopence_Command *self);
static PyObject *	Command_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static PyObject *	Command_getattr(twopence_Command *self, char *name);
static int		Command_setattr(twopence_Command *self, char *name, PyObject *);
static PyObject *	Command_suppressOutput(twopence_Command *, PyObject *, PyObject *);
static PyObject *	Command_setenv(twopence_Command *, PyObject *, PyObject *);
static PyObject *	Command_unsetenv(twopence_Command *, PyObject *, PyObject *);

/*
 * Define the Python bindings of class "Command"
 *
 * Create objects using
 *   command = twopence.Command("/bin/ls");
 *
 * Or like this:
 *   out = bytearray()
 *   err = bytearray()
 *   cmd = twopence.Command("/bin/ls", stdout = out, stderr = err, user = "wwwrun")
 *
 * Supported keyword arguments in the constructor:
 *   user
 *	The user to run this command as; default is "root"
 *   timeout
 *	The duration in seconds after which this command is aborted; default is 60L
 *   stdin
 *	The file to pass to the command's standard input. Right now,
 *	this only accepts a string specifying a path name. File or buffer
 *	objects are not supported yet.
 *   stdout, stderr:
 *	Buffers to write the respective output streams to.
 *	If not specified, output is written to the Python interpreter's stdout.
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
      {	"setenv", (PyCFunction) Command_setenv, METH_VARARGS | METH_KEYWORDS,
	"Set an environment variable to be passed to the command"
      },
      {	"unsetenv", (PyCFunction) Command_unsetenv, METH_VARARGS | METH_KEYWORDS,
	"Unset an environment variable"
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
	self->timeout = 0L;
	self->stdinPath = NULL;
	self->stdout = NULL;
	self->stderr = NULL;
	self->stdin = NULL;
	self->quiet = 0;
	self->useTty = 0;
	self->background = false;
	self->softfail = false;
	self->pid = 0;

	twopence_env_init(&self->environ);

	return (PyObject *)self;
}

/*
 * Initialize the command object
 *
 * Typical ways to do this include
 *    cmd = twopence.Command("/bin/ls", user = "wwwrun", stdout = bytearray());
 *    cmd = twopence.Command("/bin/ls", user = "wwwrun", stdout = str());
 *    cmd = twopence.Command("/usr/bin/wc", stdin = "/etc/hosts");
 */
int
Command_init(twopence_Command *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"command",
		"user",
		"timeout",
		"stdin",
		"stdout",
		"stderr",
		"suppressOutput",
		"quiet",
		"background",
		"softfail",
		NULL
	};
	PyObject *stdinObject = NULL, *stdoutObject = NULL, *stderrObject = NULL;
	char *command, *user = NULL;
	long timeout = 0L;
	int quiet = 0;
	int background = 0;
	int softfail = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|slOOOiiii", kwlist,
				&command, &user, &timeout, &stdinObject, &stdoutObject, &stderrObject,
				&quiet, &quiet,
				&background, &softfail))
		return -1;

	self->command = twopence_strdup(command);
	self->user = user? twopence_strdup(user) : NULL;
	self->timeout = timeout? timeout: 60L;
	self->stdout = NULL;
	self->stderr = NULL;
	self->stdinPath = NULL;
	self->stdin = NULL;
	self->quiet = quiet;
	self->background = background;
	self->softfail = softfail;

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

	if (stdinObject == NULL) {
		/* Default: pipe our stdin to the remote command */
	} else
	if (PyUnicode_Check(stdinObject)) {
		char *s;

		if ((s = PyUnicode_AsUTF8(stdinObject)) == NULL)
			return -1;
		self->stdinPath = twopence_strdup(s);
	} else {
		/* This can also be Py_None */
		Py_INCREF(stdinObject);
		self->stdin = stdinObject;
	}

	return 0;
}

/*
 * Destructor: clean any state inside the Command object
 */
static void
Command_dealloc(twopence_Command *self)
{
	twopence_env_destroy(&self->environ);
	drop_string(&self->command);
	drop_string(&self->user);
	drop_string(&self->stdinPath);
	drop_object(&self->stdout);
	drop_object(&self->stderr);
	drop_object(&self->stdin);
}

int
Command_Check(PyObject *self)
{
	return PyType_IsSubtype(Py_TYPE(self), &twopence_CommandType);
}

static bool
Command_redirect_iostream(twopence_command_t *cmd, twopence_iofd_t dst, PyObject *object, twopence_buf_t **buf_ret)
{
	if (object == NULL || PyByteArray_Check(object)) {
		twopence_buf_t *buffer;

		if (dst == TWOPENCE_STDIN && object == NULL)
			return true;

		/* Capture command output in a buffer */
		buffer = twopence_command_alloc_buffer(cmd, dst, 65536);
		twopence_command_ostream_capture(cmd, dst, buffer);
		if (dst == TWOPENCE_STDIN) {
			unsigned int count = PyByteArray_Size(object);

			twopence_buf_ensure_tailroom(buffer, count);
			twopence_buf_append(buffer, PyByteArray_AsString(object), count);
		}
		if (buf_ret)
			*buf_ret = buffer;
	} else
	if (PyFile_Check(object)) {
		int fd = PyObject_AsFileDescriptor(object);

		if (fd < 0) {
			/* If this fails, we could also pull the content into a buffer and then send that */
			PyErr_SetString(PyExc_TypeError, "unable to obtain file handle from File object");
			return false;
		}

		/* We dup() the file descriptor so that we no longer have to worry
		 * about what Python does with its File object */
		twopence_command_iostream_redirect(cmd, dst, dup(fd), true);
	} else
	if (object == Py_None) {
		/* Nothing */
	} else {
		/* FIXME: we could check for a string type, and in that case interpret that as
		 * the name of a file to write to. */
		PyErr_SetString(PyExc_TypeError, "invalid type in stdio attribute");
		return false;
	}

	return true;
}

int
Command_build(twopence_Command *self, twopence_command_t *cmd)
{
	twopence_buf_t *buffer = NULL;

	twopence_command_init(cmd, self->command);

	cmd->user = self->user;
	cmd->timeout = self->timeout;
	cmd->request_tty = self->useTty;
	cmd->background = self->background;

	twopence_command_ostreams_reset(cmd);
	if (self->quiet || self->stdout == Py_None) {
		/* ostream has already been reset above */
	} else {
		/* Copy remote stdout to our stdout */
		twopence_command_iostream_redirect(cmd, TWOPENCE_STDOUT, 1, false);
	}

	if (!Command_redirect_iostream(cmd, TWOPENCE_STDOUT, self->stdout, &buffer))
		return -1;

	if (self->quiet || self->stderr == Py_None) {
		/* ostream has already been reset above */
	} else {
		/* Copy remote stderr to our stderr */
		twopence_command_iostream_redirect(cmd, TWOPENCE_STDERR, 2, false);
	}

	/* If cmd.stdout and cmd.stderr are both NULL, or both refer to the same
	 * bytearray object, send the remote stdout and stderr to a shared buffer */
	if (buffer && self->stderr == self->stdout) {
		twopence_command_ostream_capture(cmd, TWOPENCE_STDERR, buffer);
	} else
	if (!Command_redirect_iostream(cmd, TWOPENCE_STDERR, self->stderr, NULL)) {
		return -1;
	}

	if (self->stdinPath != NULL) {
		int fd = open(self->stdinPath, O_RDONLY);

		if (fd < 0) {
			PyErr_SetFromErrnoWithFilename(PyExc_IOError, self->stdinPath);
			return -1;
		}
		twopence_command_iostream_redirect(cmd, TWOPENCE_STDIN, fd, true);
	} else
	if (self->stdin == Py_None) {
		/* Do not pipe anything to the command's stdin */
	} else
	if (self->stdin) {
		if (!Command_redirect_iostream(cmd, TWOPENCE_STDIN, self->stdin, NULL))
			return -1;
	} else
	if (!self->background) {
		/* Eric wants us to pipe stdin into the command by default */
		FILE *fp;
		int fd;

		fp = PySys_GetObject("stdin");
		if (fp != NULL) {
			if ((fd = fileno(fp)) < 0) {
				PyErr_SetString(PyExc_SystemError, "cannot connect command to stdin (not a regular file)");
				return -1;
			}
			/* We dup() the file descriptor so that we no longer have to worry
			 * about what Python does with its File object */
			twopence_command_iostream_redirect(cmd, TWOPENCE_STDIN, dup(fd), true);
		}
	}

	/* Copy all environment variables */
	if (self->environ.count)
		twopence_env_copy(&cmd->env, &self->environ);

	return 0;
}

static PyObject *
Command_setenv(twopence_Command *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"name",
		"value",
		NULL
	};
	const char *variable, *value = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "ss", kwlist, &variable, &value))
		return NULL;

	twopence_env_set(&self->environ, variable, value);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
Command_unsetenv(twopence_Command *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"name",
		NULL
	};
	const char *variable;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &variable))
		return NULL;

	twopence_env_unset(&self->environ, variable);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
Command_suppressOutput(twopence_Command *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		NULL
	};
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist))
		return NULL;

	self->quiet = 1;
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
		return return_string_or_none(self->command);
	if (!strcmp(name, "user"))
		return return_string_or_none(self->user);
	if (!strcmp(name, "timeout"))
		return PyLong_FromString(self->timeout, NULL, 0);
	if (!strcmp(name, "stdout"))
		return Command_stdout(self);
	if (!strcmp(name, "stderr"))
		return Command_stderr(self);
	if (!strcmp(name, "pid"))
		return PyLong_FromString(self->pid, NULL, 0);
	if (!strcmp(name, "quiet"))
		return return_bool(self->quiet);
	if (!strcmp(name, "useTty"))
		return return_bool(self->useTty);
	if (!strcmp(name, "background"))
		return return_bool(self->background);
	if (!strcmp(name, "softfail"))
		return return_bool(self->softfail);
	if (!strcmp(name, "environ")) {
		twopence_env_t *env = &self->environ;
		PyObject *rv = PyTuple_New(env->count);
		unsigned int i;

		for (i = 0; i < env->count; ++i) {
			PyObject *pair = PyTuple_New(2);
			char *name, *value;

			name = strdup(env->array[i]);
			if ((value = strchr(name, '=')) != NULL) {
				*value++ = '\0';
			} else {
				value = "undef";
			}
			PyTuple_SET_ITEM(pair, 0, PyUnicode_FromString(name));
			PyTuple_SET_ITEM(pair, 1, PyUnicode_FromString(value));
			PyTuple_SET_ITEM(rv, i, pair);
			free(name);
		}

		return rv;
	}

	return PyObject_GenericGetAttr(self, PyUnicode_FromString(name));
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
	if (!strcmp(name, "user")) {
		char *s;

		if (!PyUnicode_Check(v) || (s = PyUnicode_AsUTF8(v)) == NULL)
			goto bad_attr;
		assign_string(&self->user, s);
		return 0;
	}
	if (!strcmp(name, "timeout")) {
		if (PyLong_Check(v))
			self->timeout = PyLong_AsLong(v);
		else if (PyLong_Check(v))
			self->timeout = PyLong_AsLongLong(v);
		else
			goto bad_attr;
		return 0;
	}
	if (!strcmp(name, "quiet")) {
		self->quiet = !!(PyObject_IsTrue(v));
		return 0;
	}
	if (!strcmp(name, "useTty")) {
		self->useTty = !!(PyObject_IsTrue(v));
		return 0;
	}
	if (!strcmp(name, "background")) {
		self->background = !!(PyObject_IsTrue(v));
		return 0;
	}
	if (!strcmp(name, "softfail")) {
		self->softfail = !!(PyObject_IsTrue(v));
		return 0;
	}

	(void) PyErr_Format(PyExc_AttributeError, "Unknown attribute: %s", name);
	return -1;

bad_attr:
	(void) PyErr_Format(PyExc_AttributeError, "Incompatible value for attribute: %s", name);
	return -1;

}
