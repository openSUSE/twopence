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


#ifndef TWOPENCE_PYTHON_EXT_H
#define TWOPENCE_PYTHON_EXT_H


#include <Python.h>
#include <twopence.h>

typedef struct {
	PyObject_HEAD

	struct twopence_target *handle;
	char *		name;
	PyObject *	attrs;
} twopence_Target;

typedef struct {
	PyObject_HEAD

	char *		command;
	char *		user;
	char *		stdinPath;
	int		suppressOutput;
	PyObject *	stdout;
	PyObject *	stderr;
} twopence_Command;

typedef struct {
	PyObject_HEAD

	int		remoteStatus;
	PyObject *	stdout;
	PyObject *	stderr;
} twopence_Status;

typedef struct {
	PyObject_HEAD

	twopence_config_t *config;
} twopence_Config;



extern PyTypeObject	twopence_TargetType;
extern PyTypeObject	twopence_CommandType;
extern PyTypeObject	twopence_StatusType;
extern PyTypeObject	twopence_ConfigType;

extern int		Command_init(twopence_Command *self, PyObject *args, PyObject *kwds);
extern int		Command_Check(PyObject *);
extern int		Command_build(twopence_Command *, twopence_command_t *);
extern PyObject *	twopence_Exception(const char *msg, int rc);
extern PyObject *	twopence_callType(PyTypeObject *typeObject, PyObject *args, PyObject *kwds);

static inline void
drop_string(char **strp)
{
	if (*strp)
		free(*strp);
	*strp = NULL;
}

static inline void
assign_object(PyObject **var, PyObject *obj)
{
	if (obj) {
		Py_INCREF(obj);
	}
	if (*var) {
		Py_DECREF(*var);
	}
	*var = obj;
}

static inline void
drop_object(PyObject **var)
{
	assign_object(var, NULL);
}


#endif /* TWOPENCE_PYTHON_EXT_H */

