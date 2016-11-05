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
static int		Status_code(const twopence_Status *self);
static int		Status_nameToSignal(const char *);
static const char *	Status_signalToName(int signal);

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
	self->localError = 0;
	self->exitSignal = 0;

	self->stdout = NULL;
	self->stderr = NULL;
	self->command = NULL;
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
		"error",
		"signal",
		NULL
	};
	PyObject *stdoutObject = NULL, *stderrObject = NULL;
	const char *signalName = NULL;
	int exitval = 0, error = 0, signal = 0;

	if (args == Py_None)
		return 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iOOis", kwlist,
				&exitval, &stdoutObject, &stderrObject, &error, &signal))
		return -1;

	if (signalName) {
		signal = Status_nameToSignal(signalName);
		if (signal < 0) {
			PyErr_Format(PyExc_ValueError, "bad signal name \"%s\"", signalName);
			return -1;
		}
	}

	self->remoteStatus = exitval;
	self->localError = error;
	self->exitSignal = signal;
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
	drop_object(&self->command);
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

	if (self->exitSignal) {
		snprintf(message, sizeof(message), "crashed (received signal %s)",
				Status_signalToName(self->exitSignal));
	} else if (self->localError) {
		snprintf(message, sizeof(message), "local error: %s", twopence_strerror(self->localError));
	} else if (self->remoteStatus == 0) {
		strcpy(message, "success");
	} else {
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
		return PyInt_FromLong(Status_code(self));
	if (!strcmp(name, "localError"))
		return PyInt_FromLong(-self->localError);
	if (!strcmp(name, "exitStatus"))
		return PyInt_FromLong(self->remoteStatus);
	if (!strcmp(name, "exitSignal")) {
		if (self->exitSignal == 0) {
			Py_INCREF(Py_None);
			return Py_None;
		}
		return PyString_FromString(Status_signalToName(self->exitSignal));
	}
	if (!strcmp(name, "command")) {
		PyObject *result = self->command;

		if (result == NULL)
			result = Py_None;
		Py_INCREF(result);
		return result;
	}
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
	return (self->remoteStatus | self->localError | self->exitSignal) == 0;
}

static int
Status_code(const twopence_Status *self)
{
	if (self->exitSignal)
		return 0x100 | self->exitSignal;
	if (self->localError)
		return 0x200 | self->localError;
	return self->remoteStatus;
}

/*
 * Signal to name mapping
 */
#define SIG(NAME)	{ .no = SIG##NAME, .name = #NAME }, \
			{ .no = SIG##NAME, .name = "SIG" #NAME }

static struct signal_name {
	int no;
	const char *name;
} signal_names[] = {
	SIG(HUP),
	SIG(INT),
	SIG(QUIT),
	SIG(ILL),
	SIG(ABRT),
	SIG(FPE),
	SIG(KILL),
	SIG(SEGV),
	SIG(ALRM),
	SIG(PIPE),
	SIG(TERM),
	SIG(USR1),
	SIG(USR2),
	SIG(CHLD),
	SIG(BUS),
	{ 0, NULL }
};


static int
Status_nameToSignal(const char *name)
{
	struct signal_name *n;

	for (n = signal_names; n->name; ++n) {
		if (!strcasecmp(n->name, name))
			return n->no;
	}

	return -1;
}

static const char *
Status_signalToName(int signal)
{
	static char namebuf[16];
	struct signal_name *n;

	if (signal == 0)
		return "none";

	for (n = signal_names; n->name; ++n) {
		if (n->no == signal)
			return n->name;
	}

	snprintf(namebuf, sizeof(namebuf), "SIG%u", signal);
	return namebuf;
}
