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
#include "utils.h"

static void		Target_dealloc(twopence_Target *self);
static PyObject *	Target_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static int		Target_init(twopence_Target *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_getattr(twopence_Target *self, char *name);
static PyObject *	Target_run(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_wait(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_waitAll(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_property(twopence_Target *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_inject(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_extract(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_sendfile(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_recvfile(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Target_setenv(twopence_Target *, PyObject *, PyObject *);
static PyObject *	Target_unsetenv(twopence_Target *, PyObject *, PyObject *);
static PyObject *	Target_chat(PyObject *, PyObject *, PyObject *);

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
      {	"wait", (PyCFunction) Target_wait, METH_VARARGS | METH_KEYWORDS,
	"Wait for a backgrounded command to finish",
      },
      {	"waitAll", (PyCFunction) Target_waitAll, METH_VARARGS | METH_KEYWORDS,
	"Wait for all backgrounded commands to finish",
      },
      {	"inject", (PyCFunction) Target_inject, METH_VARARGS | METH_KEYWORDS,
	"Inject a file to the SUT"
      },
      {	"extract", (PyCFunction) Target_extract, METH_VARARGS | METH_KEYWORDS,
	"Extract a file from the SUT"
      },
      {	"sendfile", (PyCFunction) Target_sendfile, METH_VARARGS | METH_KEYWORDS,
	"Transfer a file from the local node to the SUT"
      },
      {	"recvfile", (PyCFunction) Target_recvfile, METH_VARARGS | METH_KEYWORDS,
	"Transfer a file from the SUT to the local node"
      },
      {	"setenv", (PyCFunction) Target_setenv, METH_VARARGS | METH_KEYWORDS,
	"Set an environment variable to be passed to all commands by default"
      },
      {	"unsetenv", (PyCFunction) Target_unsetenv, METH_VARARGS | METH_KEYWORDS,
	"Unset an environment variable"
      },
      {	"chat", (PyCFunction) Target_chat, METH_VARARGS | METH_KEYWORDS,
	"Create a Chat object for the given command"
      },

      {	NULL }
};

PyTypeObject twopence_TargetType = {
	PyObject_HEAD_INIT(NULL)

	.tp_name	= "twopence.Target",
	.tp_basicsize	= sizeof(twopence_Target),
	.tp_flags	= Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
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
		self->name = twopence_strdup(name);

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

	if (!strcmp(name, "name"))
		return return_string_or_none(self->name);
	if (!strcmp(name, "type"))
		return return_string_or_none(self->handle->ops->name);

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

		if (temp == NULL)
			return -1;
		if (PySequence_InPlaceConcat(buffer, temp) == NULL)
			rv = -1;
		Py_DECREF(temp);
	}
	return rv;
}

/*
 * Backgrounding commands
 */
struct backgroundedCommand *
backgroundedCommandNew(twopence_Command *cmdObject)
{
	struct backgroundedCommand *bg;

	bg = twopence_calloc(1, sizeof(*bg));
	bg->object = cmdObject;
	Py_INCREF(cmdObject);

	return bg;
}

void
backgroundedCommandFree(struct backgroundedCommand *bg)
{
	if (bg->object) {
		bg->object->pid = 0;
		Py_DECREF(bg->object);
		bg->object = NULL;
	}

	twopence_command_destroy(&bg->cmd);
	free(bg);
}

static void
Target_recordBackgrounded(twopence_Target *tgtObject, struct backgroundedCommand *bg)
{
	bg->next = tgtObject->backgrounded;
	tgtObject->backgrounded = bg;
}

static struct backgroundedCommand *
Target_findBackgrounded(twopence_Target *tgtObject, pid_t pid)
{
	struct backgroundedCommand *bg, **pos;

	for (pos = &tgtObject->backgrounded; (bg = *pos) != NULL; pos = &bg->next) {
		if (bg->pid == pid) {
			*pos = bg->next;
			bg->next = NULL;
			return bg;
		}
	}
	return NULL;
}

/*
 * Given a command and its status, build a status object
 */
static PyObject *
Target_buildCommandStatus(twopence_Command *cmdObject, twopence_command_t *cmd, twopence_status_t *status)
{
	twopence_Status *statusObject;

	/* Now funnel the captured data to the respective buffer objects */
	if (twopence_AppendBuffer(cmdObject->stdout, &cmd->buffer[TWOPENCE_STDOUT]) < 0)
		return NULL;
	if (twopence_AppendBuffer(cmdObject->stderr, &cmd->buffer[TWOPENCE_STDERR]) < 0)
		return NULL;

	statusObject = (twopence_Status *) twopence_callType(&twopence_StatusType, NULL, NULL);
	if (status->major == EFAULT) {
		/* Command exited with a signal */
		statusObject->remoteStatus = 0x100 | (status->minor & 0xFF);
	} else {
		statusObject->remoteStatus = status->minor;
	}
	if (cmdObject->stdout) {
		statusObject->stdout = cmdObject->stdout;
		Py_INCREF(statusObject->stdout);
	}
	if (cmdObject->stderr) {
		statusObject->stderr = cmdObject->stderr;
		Py_INCREF(statusObject->stderr);
	}
	statusObject->command = (PyObject *) cmdObject;
	Py_INCREF(cmdObject);

	return (PyObject *) statusObject;
}

static twopence_Status *
Target_buildCommandStatusShort(twopence_Command *cmdObject, twopence_command_t *cmd, twopence_status_t *status)
{
	twopence_Status *statusObject;

	/* Now funnel the captured data to the respective buffer objects */
	if (twopence_AppendBuffer(cmdObject->stdout, &cmd->buffer[TWOPENCE_STDOUT]) < 0)
		return NULL;
	if (twopence_AppendBuffer(cmdObject->stderr, &cmd->buffer[TWOPENCE_STDERR]) < 0)
		return NULL;

	statusObject = (twopence_Status *) twopence_callType(&twopence_StatusType, NULL, NULL);
	statusObject->remoteStatus = status->minor;

	return statusObject;
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
		cmdObject = (twopence_Command *) twopence_callType(&twopence_CommandType, args, kwds);
		if (cmdObject == NULL)
			goto out;
	}

	if (cmdObject->pid != 0) {
		PyErr_SetString(PyExc_SystemError, "Command already executing");
		goto out;
	}

	if ((handle = Target_handle(self)) == NULL)
		goto out;

	memset(&cmd, 0, sizeof(cmd));
	if (cmdObject->background) {
		twopence_Target *tgtObject = (twopence_Target *) self;
		struct backgroundedCommand *bg;

		bg = backgroundedCommandNew(cmdObject);
		if (Command_build(cmdObject, &bg->cmd) < 0) {
			backgroundedCommandFree(bg);
			goto out;
		}

		rc = twopence_run_test(handle, &bg->cmd, &status);
		if (rc < 0) {
			twopence_Exception("run(background)", rc);
			backgroundedCommandFree(bg);
			goto out;
		}
		if (rc == 0) {
			PyErr_SetString(PyExc_SystemError, "Target.run() of a backgrounded command returns pid 0");
			backgroundedCommandFree(bg);
			goto out;
		}

		Target_recordBackgrounded(tgtObject, bg);
		bg->pid = rc;

		cmdObject->pid = bg->pid;

		result = Py_True;
		Py_INCREF(result);
	} else {
		if (Command_build(cmdObject, &cmd) < 0)
			goto out;

		rc = twopence_run_test(handle, &cmd, &status);
		if (rc < 0) {
			twopence_Exception("run", rc);
			goto out;
		}

		result = Target_buildCommandStatus(cmdObject, &cmd, &status);
	}

out:
	if (cmdObject) {
		Py_DECREF(cmdObject);
	}

	twopence_command_destroy(&cmd);
	return result;
}

/*
 * Wait for command(s) to complete
 */
PyObject *
Target_wait_common(twopence_Target *tgtObject, int pid)
{
	struct twopence_target *handle;
	struct backgroundedCommand *bg;
	PyObject *result;
	twopence_status_t status;

	if ((handle = tgtObject->handle) == NULL)
		return NULL;

	pid = twopence_wait(handle, pid, &status);
	if (pid < 0)
		return twopence_Exception("wait", pid);

	if (pid == 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	bg = Target_findBackgrounded(tgtObject, pid);
	if (bg == NULL) {
		PyErr_SetString(PyExc_SystemError, "Target.wait(): No record of PID returned by target");
		return NULL;
	}

	result = Target_buildCommandStatus(bg->object, &bg->cmd, &status);
	backgroundedCommandFree(bg);

	return result;
}

static PyObject *
Target_wait(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"command",
		NULL
	};
	twopence_Target *tgtObject = (twopence_Target *) self;
	PyObject *argObject = NULL;
	int pid = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O", kwlist, &argObject))
		return NULL;

	if (argObject == NULL) {
		pid = 0;
	} else if (PyInt_Check(argObject)) {
		pid = PyInt_AsLong(argObject);

		if (pid < 0) {
			PyErr_SetString(PyExc_ValueError, "target.wait(): pid must not be negative");
			return NULL;
		}
	} else if (Command_Check(argObject)) {
		pid = ((twopence_Command *) argObject)->pid;
		if (pid == 0) {
			PyErr_SetString(PyExc_ValueError,
				"target.wait(): no running command matching this argument");
			return NULL;
		}
	} else {
		PyErr_SetString(PyExc_TypeError,
				"target.wait(): Invalid argument type");
		return NULL;
	}

	return Target_wait_common(tgtObject, pid);
}

/*
 * Wait for all commands to complete
 */
static PyObject *
Target_waitAll(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"print_dots",
		NULL
	};
	twopence_target_t *handle;
	twopence_Target *tgtObject = (twopence_Target *) self;
	twopence_Status *result = NULL;
	int print_dots = 0, ndots = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &print_dots))
		return NULL;

	if ((handle = Target_handle(self)) == NULL)
		return NULL;

	while (true) {
		struct backgroundedCommand *bg;
		twopence_status_t status;
		int pid = 0;

		pid = twopence_wait(handle, 0, &status);
		if (pid < 0) {
			if (ndots)
				printf("\n");
			return twopence_Exception("wait", pid);
		}

		if (pid == 0) {
			if (ndots)
				printf("\n");
			break;
		}

		bg = Target_findBackgrounded(tgtObject, pid);
		if (bg == NULL) {
			if (ndots)
				printf("\n");
			PyErr_SetString(PyExc_SystemError, "Target.wait(): No record of PID returned by target");
			return NULL;
		}

		if (result == NULL)
			result = Target_buildCommandStatusShort(bg->object, &bg->cmd, &status);
		if (status.major == EFAULT) {
			/* Command exited with a signal */
			result->remoteStatus = 0x100 | (status.minor & 0xFF);
		} else if (status.minor) {
			result->remoteStatus = status.minor;
		}

		backgroundedCommandFree(bg);
		if (print_dots) {
			fputc('.', stdout);
			fflush(stdout);
			ndots++;
		}
	}

	if (result == NULL) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	return (PyObject *) result;
}

static PyObject *
Target_chat(PyObject *self, PyObject *args, PyObject *kwds)
{
	twopence_Target *tgtObject = (twopence_Target *) self;
	twopence_Command *cmdObject = NULL;
	twopence_Chat *chatObject = NULL;
	struct backgroundedCommand *bg = NULL;
	PyObject *result = NULL;
	int rc;

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

	if (cmdObject->pid != 0) {
		PyErr_SetString(PyExc_SystemError, "Command already executing");
		goto out;
	}

	bg = backgroundedCommandNew(cmdObject);
	if (Command_build(cmdObject, &bg->cmd) < 0)
		goto failed;

	chatObject = (twopence_Chat *) twopence_callType(&twopence_ChatType, NULL, NULL);
	if (chatObject == NULL)
		goto failed;

	chatObject->target = tgtObject;
	Py_INCREF(tgtObject);

	twopence_chat_init(&chatObject->chat,
			twopence_command_alloc_buffer(&bg->cmd, TWOPENCE_STDIN, 65536),
			twopence_command_alloc_buffer(&bg->cmd, TWOPENCE_STDOUT, 65536));

	rc = twopence_chat_begin(tgtObject->handle, &bg->cmd, &chatObject->chat);
	if (rc < 0) {
		twopence_Exception("chat()", rc);
		goto failed;
	}
	if (rc == 0) {
		PyErr_SetString(PyExc_SystemError, "Target.chat() of a backgrounded command returns pid 0");
		goto failed;
	}

	Target_recordBackgrounded(tgtObject, bg);
	bg->pid = rc;

	cmdObject->pid = bg->pid;
	chatObject->pid = bg->pid;

	chatObject->command = cmdObject;
	Py_INCREF(cmdObject);

	result = (PyObject *) chatObject;

out:
	if (cmdObject) {
		Py_DECREF(cmdObject);
	}

	return result;

failed:
	if (bg)
		backgroundedCommandFree(bg);
	if (chatObject) {
		Py_DECREF(chatObject);
	}
	goto out;
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

	/* printf("inject %s -> %s (user %s, mode 0%o)\n", sourceFile, destFile, user, omode); */

	if ((handle = Target_handle(self)) == NULL)
		return NULL;

	rc = twopence_inject_file(handle, user, sourceFile, destFile, &remoteRc, 0);
	if (rc < 0)
		return twopence_Exception("inject", rc);

	return PyInt_FromLong(remoteRc);
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

	/* printf("extract %s -> %s (user %s, mode 0%o)\n", sourceFile, destFile, user, omode); */
	if ((handle = Target_handle(self)) == NULL)
		return NULL;

	rc = twopence_extract_file(handle, user, sourceFile, destFile, &remoteRc, 0);
	if (rc < 0)
		return twopence_Exception("extract", rc);

	return PyInt_FromLong(remoteRc);
}

/*
 * Common functionality for sendfile/recvfile
 */
static PyObject *
Taget_send_recv_common(PyObject *args, PyObject *kwds)
{
	PyObject *xferObject = NULL;

	if (PySequence_Check(args)
	 && PySequence_Fast_GET_SIZE(args) == 1) {
		/* Single argument can be an object of type Command or a string */
		PyObject *object = PySequence_Fast_GET_ITEM(args, 0);

		if (Transfer_Check(object)) {
			xferObject = object;
			Py_INCREF(xferObject);
		}
	}

	if (xferObject == NULL)
		xferObject = twopence_callType(&twopence_TransferType, args, kwds);

	return xferObject;
}

/*
 * transfer a file to the SUT
 */
static PyObject *
Target_sendfile(PyObject *self, PyObject *args, PyObject *kwds)
{
	struct twopence_target *handle;
	twopence_Transfer *xferObject = NULL;
	twopence_Status *statusObject;
	twopence_file_xfer_t xfer;
	twopence_status_t status;
	PyObject *result = NULL;
	int rc;

	twopence_file_xfer_init(&xfer);

	xferObject = (twopence_Transfer *) Taget_send_recv_common(args, kwds);
	if (xferObject == NULL)
		goto out;

	if (Transfer_build_send(xferObject, &xfer) < 0)
		goto out;

	if ((handle = Target_handle(self)) == NULL)
		return NULL;

	rc = twopence_send_file(handle, &xfer, &status);
	if (rc < 0) {
		twopence_Exception("sendfile", rc);
		goto out;
	}

	statusObject = (twopence_Status *) twopence_callType(&twopence_StatusType, NULL, NULL);
	statusObject->remoteStatus = status.major ?: status.minor;
	result = (PyObject *) statusObject;

out:
	if (xferObject) {
		Py_DECREF(xferObject);
	}

	twopence_file_xfer_destroy(&xfer);
	return result;
}

/*
 * transfer a file to the SUT
 */
static PyObject *
Target_recvfile(PyObject *self, PyObject *args, PyObject *kwds)
{
	struct twopence_target *handle;
	twopence_Transfer *xferObject = NULL;
	twopence_Status *statusObject;
	twopence_file_xfer_t xfer;
	twopence_status_t status;
	PyObject *result = NULL;
	int rc;

	twopence_file_xfer_init(&xfer);

	xferObject = (twopence_Transfer *) Taget_send_recv_common(args, kwds);
	if (xferObject == NULL)
		goto out;

	if (Transfer_build_recv(xferObject, &xfer) < 0)
		goto out;

	if ((handle = Target_handle(self)) == NULL)
		return NULL;

	rc = twopence_recv_file(handle, &xfer, &status);
	if (rc < 0) {
		twopence_Exception("recvfile", rc);
		goto out;
	}

	statusObject = (twopence_Status *) twopence_callType(&twopence_StatusType, NULL, NULL);
	statusObject->remoteStatus = status.major ?: status.minor;

	/* If we didn't write to a local file, we sent our data to self->databuf.
	 * copy that back to the data buffer, and return it in the status object */
	if (statusObject->remoteStatus == 0 && xferObject->local_filename == NULL) {
		if (xferObject->buffer && PyByteArray_Check(xferObject->buffer)) {
			statusObject->buffer = xferObject->buffer;
			Py_INCREF(xferObject->buffer);
		} else {
			statusObject->buffer = twopence_callType(&PyByteArray_Type, NULL, NULL);
		}
		twopence_AppendBuffer(statusObject->buffer, &xferObject->databuf);
	}
	result = (PyObject *) statusObject;

out:
	if (xferObject) {
		Py_DECREF(xferObject);
	}

	twopence_file_xfer_destroy(&xfer);
	return result;
}

static PyObject *
Target_setenv(twopence_Target *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"name",
		"value",
		NULL
	};
	const char *variable, *value = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "ss", kwlist, &variable, &value))
		return NULL;

	twopence_target_setenv(self->handle, variable, value);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
Target_unsetenv(twopence_Target *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"name",
		NULL
	};
	const char *variable;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &variable))
		return NULL;

	twopence_target_setenv(self->handle, variable, NULL);

	Py_INCREF(Py_None);
	return Py_None;
}
