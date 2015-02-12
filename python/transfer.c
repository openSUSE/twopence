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

#include "twopence.h"

static void		Transfer_dealloc(twopence_Transfer *self);
static PyObject *	Transfer_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static PyObject *	Transfer_getattr(twopence_Transfer *self, char *name);
static int		Transfer_setattr(twopence_Transfer *self, char *name, PyObject *);

/*
 * Define the python bindings of class "Transfer"
 *
 * Create objects using
 *   xfer = twopence.Transfer(remotefile = "/tmp/foobar", localfile = "mytemplate");
 *
 * Use in sendfile/recvfile calls like this:
 *   status = target.sendfile(xfer)
 * or
 *   status = target.recvfile(xfer)
 *
 * Supported keyword arguments in the constructor:
 *   remotefile
 *	Name of the remote file (mandatory)
 *   permissions
 *	Unix permission bits of the file to be created (remotely or locally)
 *   user
 *	The user to run this command as; default is "root"
 *   data
 *	Local data buffer.
 *   localfile
 *	Name of the local file to upload from or download to.
 *	If not provided:
 *	 - send() will fail
 *	 - recv() will download the file contents to a data buffer.
 */
static PyMethodDef twopence_transferMethods[] = {
      {	NULL }
};

PyTypeObject twopence_TransferType = {
	PyObject_HEAD_INIT(NULL)

	.tp_name	= "twopence.Transfer",
	.tp_basicsize	= sizeof(twopence_Transfer),
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "Twopence transfer",

	.tp_methods	= twopence_transferMethods,
	.tp_init	= (initproc) Transfer_init,
	.tp_new		= Transfer_new,
	.tp_dealloc	= (destructor) Transfer_dealloc,

	.tp_getattr	= (getattrfunc) Transfer_getattr,
	.tp_setattr	= (setattrfunc) Transfer_setattr,
};

/*
 * Constructor: allocate empty Transfer object, and set its members.
 */
static PyObject *
Transfer_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	twopence_Transfer *self;

	self = (twopence_Transfer *) type->tp_alloc(type, 0);
	if (self == NULL)
		return NULL;

	/* init members */
	self->remote_filename = NULL;
	self->local_filename = NULL;
	self->permissions = 0;
	self->user = NULL;
	self->timeout = 0L;
	self->buffer = NULL;

	return (PyObject *)self;
}

/*
 * Initialize the transfer object
 *
 * Typical ways to do this include
 *    cmd = twopence.Transfer("/bin/ls", user = "wwwrun", stdout = bytearray());
 *    cmd = twopence.Transfer("/bin/ls", user = "wwwrun", stdout = str());
 *    cmd = twopence.Transfer("/usr/bin/wc", stdin = "/etc/hosts");
 */
int
Transfer_init(twopence_Transfer *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"remotefile",
		"user",
		"localfile",
		"permissions",
		"timeout",
		"data",
		NULL
	};
	PyObject *bufferObject = NULL;
	char *remotefile = NULL, *localfile = NULL, *user = NULL;
	long permissions = 0L, timeout = 0L;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|ssllO", kwlist, &remotefile, &user, &localfile, &permissions, &timeout, &bufferObject))
		return -1;

	self->remote_filename = strdup(remotefile);
	self->local_filename = strdup(localfile);
	self->user = user? strdup(user) : NULL;
	self->permissions = permissions;
	self->timeout = timeout;
	self->buffer = NULL;

	return 0;
}

/*
 * Destructor: clean any state inside the Transfer object
 */
static void
Transfer_dealloc(twopence_Transfer *self)
{
	drop_string(&self->remote_filename);
	drop_string(&self->local_filename);
	drop_string(&self->user);
	drop_object(&self->buffer);
}

int
Transfer_Check(PyObject *self)
{
	return PyType_IsSubtype(Py_TYPE(self), &twopence_TransferType);
}

int
Transfer_build_send(twopence_Transfer *self, twopence_file_xfer_t *xfer)
{
	twopence_file_xfer_init(xfer);

	xfer->remote.name = self->remote_filename;
	xfer->remote.mode = self->permissions;
	xfer->user = self->user;
	/* xfer->timeout = self->timeout; */

	if (self->local_filename) {
		int rv;

		rv = twopence_iostream_open_file(self->local_filename, &xfer->local_stream);
		if (rv < 0)
			return -1;
	} else if (self->buffer != NULL) {
		/* TBD: implement an iostream type that can read from a python buffer */
		return -1;
	} else {
		/* We don't know what to send */
		return -1;
	}

	return 0;
}


int
Transfer_build_recv(twopence_Transfer *self, twopence_file_xfer_t *xfer)
{
	twopence_file_xfer_init(xfer);

	xfer->remote.name = self->remote_filename;
	xfer->user = self->user;
	/* xfer->timeout = self->timeout; */

	xfer->remote.mode = self->permissions;
	if (self->local_filename) {
		int rv;

		rv = twopence_iostream_create_file(self->local_filename, self->permissions, &xfer->local_stream);
		if (rv < 0)
			return -1;
	} else {
		/* TBD: implement an iostream type that can write to a python buffer */
		return -1;
	}

	return 0;
}

static PyObject *
Transfer_data(twopence_Transfer *self)
{
	PyObject *result;

	result = self->buffer;
	if (result == NULL)
		result = Py_None;
	Py_INCREF(result);
	return result;
}

static PyObject *
Transfer_getattr(twopence_Transfer *self, char *name)
{
	if (!strcmp(name, "remotefile"))
		return PyString_FromString(self->remote_filename);
	if (!strcmp(name, "localfile"))
		return PyString_FromString(self->local_filename);
	if (!strcmp(name, "user"))
		return PyString_FromString(self->user);
	if (!strcmp(name, "permissions"))
		return PyInt_FromLong(self->permissions);
	if (!strcmp(name, "timeout"))
		return PyInt_FromLong(self->timeout);
	if (!strcmp(name, "data"))
		return Transfer_data(self);

	return Py_FindMethod(twopence_transferMethods, (PyObject *) self, name);
}

static int
Transfer_setattr(twopence_Transfer *self, char *name, PyObject *v)
{
	if (!strcmp(name, "remotefile")) {
		char *s;

		if (!PyString_Check(v) || (s = PyString_AsString(v)) == NULL)
			goto bad_attr;
		assign_string(&self->remote_filename, s);
		return 0;
	}
	if (!strcmp(name, "localfile")) {
		char *s;

		if (!PyString_Check(v) || (s = PyString_AsString(v)) == NULL)
			goto bad_attr;
		assign_string(&self->local_filename, s);
		return 0;
	}
	if (!strcmp(name, "user")) {
		char *s;

		if (!PyString_Check(v) || (s = PyString_AsString(v)) == NULL)
			goto bad_attr;
		assign_string(&self->user, s);
		return 0;
	}
	if (!strcmp(name, "permissions")) {
		if (!PyInt_Check(v))
			goto bad_attr;
		self->permissions = PyInt_AsLong(v);
		return 0;
	}
	if (!strcmp(name, "timeout")) {
		if (!PyInt_Check(v))
			goto bad_attr;
		self->timeout = PyInt_AsLong(v);
		return 0;
	}
	if (!strcmp(name, "data")) {
		if (v != Py_None && !PyByteArray_Check(v))
			goto bad_attr;
		assign_object(&self->buffer, v);
		return 0;
	}

	(void) PyErr_Format(PyExc_AttributeError, "Unknown attribute: %s", name);
	return -1;

bad_attr:
	(void) PyErr_Format(PyExc_AttributeError, "Incompatible value for attribute: %s", name);
	return -1;

}
