/*
Twopence python bindings - extension glue

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


static PyObject *	twopence_setDebugLevel(PyObject *, PyObject *, PyObject *);

/*
 * Methods belonging to the module itself.
 */
static PyMethodDef twopence_methods[] = {
      {	"setDebugLevel", (PyCFunction) twopence_setDebugLevel, METH_VARARGS | METH_KEYWORDS,
	"Set the debug level (0 is no debugging)"
      },
      {	NULL }
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
# define PyMODINIT_FUNC void
#endif

/*
 * Convert twopence error to an exception
 */
PyObject *
twopence_Exception(const char *msg, int rc)
{
	char buffer[256];

	snprintf(buffer, sizeof(buffer), "%s: %s", msg, twopence_strerror(rc));
	PyErr_SetString(PyExc_SystemError, buffer);
	return NULL;
}

static PyObject *
twopence_setDebugLevel(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"level",
		NULL
	};
	int level;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &level))
		return NULL;

	twopence_debug_level = level;
	Py_INCREF(Py_None);
	return Py_None;

}

static void
twopence_registerType(PyObject *m, const char *name, PyTypeObject *type)
{
	if (PyType_Ready(type) < 0)
		return;

	Py_INCREF(type);
	PyModule_AddObject(m, name, (PyObject *) type);
}

#define DECLARE_ERROR(x) \
	{ TWOPENCE_##x, #x }

static void
twopence_registerErrorConstants(PyObject *m)
{
	struct map {
		int		code;
		const char *	name;
	};
	struct map errorMap[] = {
		DECLARE_ERROR(PARAMETER_ERROR),
		DECLARE_ERROR(OPEN_SESSION_ERROR),
		DECLARE_ERROR(SEND_COMMAND_ERROR),
		DECLARE_ERROR(FORWARD_INPUT_ERROR),
		DECLARE_ERROR(RECEIVE_RESULTS_ERROR),
		DECLARE_ERROR(COMMAND_TIMEOUT_ERROR),
		DECLARE_ERROR(LOCAL_FILE_ERROR),
		DECLARE_ERROR(SEND_FILE_ERROR),
		DECLARE_ERROR(REMOTE_FILE_ERROR),
		DECLARE_ERROR(RECEIVE_FILE_ERROR),
		DECLARE_ERROR(INTERRUPT_COMMAND_ERROR),
		DECLARE_ERROR(INVALID_TARGET_ERROR),
		DECLARE_ERROR(UNKNOWN_PLUGIN_ERROR),
		DECLARE_ERROR(INCOMPATIBLE_PLUGIN_ERROR),
		DECLARE_ERROR(UNSUPPORTED_FUNCTION_ERROR),
		DECLARE_ERROR(PROTOCOL_ERROR),
		DECLARE_ERROR(INTERNAL_ERROR),
		DECLARE_ERROR(TRANSPORT_ERROR),
		DECLARE_ERROR(INCOMPATIBLE_PROTOCOL_ERROR),
		DECLARE_ERROR(INVALID_TRANSACTION),
		DECLARE_ERROR(COMMAND_CANCELED_ERROR),
		{ -1, NULL }
	};
	struct map *em;

	for (em = errorMap; em->name; ++em)
		PyModule_AddIntConstant(m, em->name, -em->code);
}

PyObject *
twopence_callObject(PyObject *callable, PyObject *args, PyObject *kwds)
{
	PyObject *obj;

	if (args == NULL) {
		args = PyTuple_New(0);
		obj = PyObject_Call(callable, args, NULL);
		Py_DECREF(args);
	} else {
		obj = PyObject_Call(callable, args, kwds);
	}

	return obj;
}

PyObject *
twopence_callType(PyTypeObject *typeObject, PyObject *args, PyObject *kwds)
{
	return twopence_callObject((PyObject *) typeObject, args, kwds);
}

PyMODINIT_FUNC
inittwopence(void) 
{
	PyObject* m;

	m = Py_InitModule3("twopence", twopence_methods, "Module for twopence based testing");

	twopence_registerType(m, "Target", &twopence_TargetType);
	twopence_registerType(m, "Command", &twopence_CommandType);
	twopence_registerType(m, "Transfer", &twopence_TransferType);
	twopence_registerType(m, "Status", &twopence_StatusType);
	twopence_registerType(m, "Chat", &twopence_ChatType);
	twopence_registerType(m, "Timer", &twopence_TimerType);

	twopence_registerErrorConstants(m);
}
