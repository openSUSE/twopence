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
PyObject *
twopence_Exception(const char *msg, int rc)
{
	char buffer[256];

	snprintf(buffer, sizeof(buffer), "%s: %s", msg, twopence_strerror(rc));
	PyErr_SetString(PyExc_SystemError, buffer);
	return NULL;
}

static void
twopence_registerType(PyObject *m, const char *name, PyTypeObject *type)
{
	if (PyType_Ready(type) < 0)
		return;

	Py_INCREF(type);
	PyModule_AddObject(m, name, (PyObject *) type);
}

PyObject *
twopence_callType(PyTypeObject *typeObject, PyObject *args, PyObject *kwds)
{
	PyObject *obj;

	if (args == NULL) {
		args = PyTuple_New(0);
		obj = PyObject_Call((PyObject *) typeObject, args, NULL);
		Py_DECREF(args);
	} else {
		obj = PyObject_Call((PyObject *) typeObject, args, kwds);
	}

	return obj;
}

PyMODINIT_FUNC
inittwopence(void) 
{
	PyObject* m;

	m = Py_InitModule3("twopence", twopence_methods, "Module for twopence based testing");

	twopence_registerType(m, "Target", &twopence_TargetType);
	twopence_registerType(m, "Command", &twopence_CommandType);
	twopence_registerType(m, "Status", &twopence_StatusType);
}
