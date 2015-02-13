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
#include <string.h>

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
	long		timeout;
	char *		stdinPath;
	int		suppressOutput;
	PyObject *	stdout;
	PyObject *	stderr;
	PyObject *	stdin;
	bool		useTty;
} twopence_Command;

typedef struct {
	PyObject_HEAD

	char *		remote_filename;
	unsigned int	permissions;
	char *		user;
	long		timeout;
	char *		local_filename;
	PyObject *	buffer;

	twopence_buf_t	databuf;
} twopence_Transfer;

typedef struct {
	PyObject_HEAD

	int		remoteStatus;
	/* for cmd operations */
	PyObject *	stdout;
	PyObject *	stderr;
	/* for xfer operations */
	PyObject *	buffer;
} twopence_Status;



extern PyTypeObject	twopence_TargetType;
extern PyTypeObject	twopence_CommandType;
extern PyTypeObject	twopence_TransferType;
extern PyTypeObject	twopence_StatusType;

extern int		Command_init(twopence_Command *self, PyObject *args, PyObject *kwds);
extern int		Command_Check(PyObject *);
extern int		Command_build(twopence_Command *, twopence_command_t *);
extern int		Transfer_init(twopence_Transfer *self, PyObject *args, PyObject *kwds);
extern int		Transfer_Check(PyObject *);
extern int		Transfer_build_send(twopence_Transfer *, twopence_file_xfer_t *);
extern int		Transfer_build_recv(twopence_Transfer *, twopence_file_xfer_t *);
extern PyObject *	twopence_Exception(const char *msg, int rc);
extern PyObject *	twopence_callType(PyTypeObject *typeObject, PyObject *args, PyObject *kwds);

static inline void
assign_string(char **var, char *str)
{
	if (*var == str)
		return;
	if (str)
		str = strdup(str);
	if (*var)
		free(*var);
	*var = str;
}

static inline void
drop_string(char **var)
{
	assign_string(var, NULL);
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

