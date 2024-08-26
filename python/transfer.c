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

static void		Transfer_dealloc(twopence_Transfer *self);
static PyObject *	Transfer_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static PyObject *	Transfer_getattr(twopence_Transfer *self, char *name);
static int		Transfer_setattr(twopence_Transfer *self, char *name, PyObject *);

/*
 * Define the Python bindings of class "Transfer"
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

	twopence_buf_init(&self->databuf);

	return (PyObject *)self;
}

/*
 * Initialize the transfer object
 *
 * Typical ways to do this include
 *    xfer = twopence.Transfer("etc/hosts", user = "joedoe");
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

	self->remote_filename = twopence_strdup(remotefile);
	self->local_filename = localfile? twopence_strdup(localfile) : NULL;
	self->user = user? twopence_strdup(user) : NULL;
	self->permissions = permissions;
	self->timeout = timeout;
	self->buffer = bufferObject;
	if (bufferObject) {
		Py_INCREF(bufferObject);
	}

	twopence_buf_init(&self->databuf);

	return 0;
}

/*
 * Destructor: clean any state inside the Transfer object
 */
static void
Transfer_dealloc(twopence_Transfer *self)
{
	twopence_buf_destroy(&self->databuf);
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
	} else if (self->buffer != NULL && PyByteArray_Check(self->buffer)) {
		unsigned int count;

		twopence_buf_destroy(&self->databuf);

		count = PyByteArray_Size(self->buffer);
		twopence_buf_ensure_tailroom(&self->databuf, count);
		twopence_buf_append(&self->databuf, PyByteArray_AsString(self->buffer), count);
		if (twopence_iostream_wrap_buffer(&self->databuf, false, &xfer->local_stream) < 0) {
			PyErr_SetString(PyExc_TypeError, "Cannot convert xfer buffer");
			return -1;
		}
	} else {
		/* We don't know what to send */
		PyErr_SetString(PyExc_TypeError, "Transfer object specifies neither localfile nor buffer");
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
		if (twopence_iostream_wrap_buffer(&self->databuf, true, &xfer->local_stream) < 0)
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
		return return_string_or_none(self->remote_filename);
	if (!strcmp(name, "localfile"))
		return return_string_or_none(self->local_filename);
	if (!strcmp(name, "user"))
		return return_string_or_none(self->user);
	if (!strcmp(name, "permissions"))
		return PyLong_FromString(self->permissions, NULL, 0);
	if (!strcmp(name, "timeout"))
		return PyLong_FromString(self->timeout, NULL, 0);
	if (!strcmp(name, "data"))
		return Transfer_data(self);

	return PyObject_GenericGetAttr(self, PyUnicode_FromString(name));
}

static int
Transfer_setattr(twopence_Transfer *self, char *name, PyObject *v)
{
	if (!strcmp(name, "remotefile")) {
		char *s;

		if (!PyUnicode_Check(v) || (s = PyUnicode_AsUTF8(v)) == NULL)
			goto bad_attr;
		assign_string(&self->remote_filename, s);
		return 0;
	}
	if (!strcmp(name, "localfile")) {
		char *s;

		if (!PyUnicode_Check(v) || (s = PyUnicode_AsUTF8(v)) == NULL)
			goto bad_attr;
		assign_string(&self->local_filename, s);
		return 0;
	}
	if (!strcmp(name, "user")) {
		char *s;

		if (!PyUnicode_Check(v) || (s = PyUnicode_AsUTF8(v)) == NULL)
			goto bad_attr;
		assign_string(&self->user, s);
		return 0;
	}
	if (!strcmp(name, "permissions")) {
		if (!PyLong_Check(v))
			goto bad_attr;
		self->permissions = PyLong_AsLong(v);
		return 0;
	}
	if (!strcmp(name, "timeout")) {
		if (!PyLong_Check(v))
			goto bad_attr;
		self->timeout = PyLong_AsLong(v);
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
