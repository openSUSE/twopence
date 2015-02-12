/*
Twopence python bindings - class Status

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

static void		Status_dealloc(twopence_Status *self);
static PyObject *	Status_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static int		Status_init(twopence_Status *self, PyObject *args, PyObject *kwds);
static PyObject *	Status_getattr(twopence_Status *self, char *name);
static int		Status_nonzero(twopence_Status *);

/*
 * Define the python bindings of class "Status"
 * Normally, you do not create Status objects yourself;
 * Usually, these are created as the return value of Command.run()
 */
static PyMethodDef twopence_statusMethods[] = {
      {	NULL }
};

static PyNumberMethods twopence_statusAsNumber = {
	.nb_nonzero	= (inquiry) Status_nonzero,
};

PyTypeObject twopence_StatusType = {
	PyObject_HEAD_INIT(NULL)

	.tp_name	= "twopence.Status",
	.tp_basicsize	= sizeof(twopence_Status),
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "Twopence status",

	.tp_methods	= twopence_statusMethods,
	.tp_init	= (initproc) Status_init,
	.tp_new		= Status_new,
	.tp_dealloc	= (destructor) Status_dealloc,

	.tp_getattr	= (getattrfunc) Status_getattr,
	.tp_as_number	= &twopence_statusAsNumber,
};

/*
 * Constructor: allocate empty Status object, and set its members.
 */
static PyObject *
Status_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	twopence_Status *self;

	self = (twopence_Status *) type->tp_alloc(type, 0);
	if (self == NULL)
		return NULL;

	/* init members */
	self->remoteStatus = 0;
	self->stdout = NULL;
	self->stderr = NULL;
	self->buffer = NULL;

	return (PyObject *)self;
}

/*
 * Initialize the status object
 */
static int
Status_init(twopence_Status *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"status",
		"stdout",
		"stderr",
		NULL
	};
	PyObject *stdoutObject = NULL, *stderrObject = NULL;
	int exitval = 0;

	if (args == Py_None)
		return 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iOO", kwlist, &exitval, &stdoutObject, &stderrObject))
		return -1;

	self->remoteStatus = exitval;
	self->stdout = NULL;
	self->stderr = NULL;
	self->buffer = NULL;

	if (stdoutObject) {
		Py_INCREF(stdoutObject);
		self->stdout = stdoutObject;
	}
	if (stderrObject) {
		Py_INCREF(stderrObject);
		self->stderr = stderrObject;
	}

	return 0;
}

/*
 * Destructor: clean any state inside the Status object
 */
static void
Status_dealloc(twopence_Status *self)
{
	drop_object(&self->stdout);
	drop_object(&self->stderr);
	drop_object(&self->buffer);
}

int
Status_Check(PyObject *self)
{
	return PyType_IsSubtype(Py_TYPE(self), &twopence_StatusType);
}

static PyObject *
Status_object_attr(twopence_Status *self, PyObject *result)
{
	if (result == NULL)
		result = Py_None;
	Py_INCREF(result);
	return result;
}

static PyObject *
Status_message(twopence_Status *self)
{
	char message[128];

	message[0] = '\0';

	/* Unfortunately, the exit status returned by libssh is somewhat limited :-( */
	switch (self->remoteStatus) {
	case 0:
		strcpy(message, "success");
		break;

	case -1:
		strcpy(message, "crashed");
		break;

	default:
		snprintf(message, sizeof(message), "status %d", self->remoteStatus);
	}

	return PyString_FromString(message);
}

static PyObject *
Status_getattr(twopence_Status *self, char *name)
{
	if (!strcmp(name, "stdout"))
		return Status_object_attr(self, self->stdout);
	if (!strcmp(name, "stderr"))
		return Status_object_attr(self, self->stderr);
	if (!strcmp(name, "buffer"))
		return Status_object_attr(self, self->buffer);
	if (!strcmp(name, "code"))
		return PyInt_FromLong(self->remoteStatus);
	if (!strcmp(name, "message"))
		return Status_message(self);

	PyErr_Format(PyExc_AttributeError, "%s", name);
	return NULL;
}

/*
 * Support using a status object in a boolean context, as in
 *
 * status = target.run(cmd)
 * if status:
 *    all is well
 *
 */
static int
Status_nonzero(twopence_Status *self)
{
	return self->remoteStatus == 0;
}
