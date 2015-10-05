/*
Twopence python bindings - class Chat

Copyright (C) 2015 SUSE

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

static void		Chat_dealloc(twopence_Chat *self);
static PyObject *	Chat_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static int		Chat_init(twopence_Chat *self, PyObject *args, PyObject *kwds);
static PyObject *	Chat_expect(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Chat_send(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Chat_recvline(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Chat_wait(PyObject *self, PyObject *args, PyObject *kwds);
static PyObject *	Chat_getattr(twopence_Chat *self, char *name);

/*
 * Define the python bindings of class "Chat"
 * Normally, you do not create Chat objects yourself;
 * Usually, these are created as the return value of Command.chat()
 */
static PyMethodDef twopence_chatMethods[] = {
      {	"expect", (PyCFunction) Chat_expect, METH_VARARGS | METH_KEYWORDS,
	"Wait for the command to print a given string"
      },
      {	"send", (PyCFunction) Chat_send, METH_VARARGS | METH_KEYWORDS,
	"Send a string to the command's standard input"
      },
      {	"recvline", (PyCFunction) Chat_recvline, METH_VARARGS | METH_KEYWORDS,
	"Receive a line of text from the command's output"
      },
      { "wait", (PyCFunction) Chat_wait, METH_VARARGS | METH_KEYWORDS,
	"Wait for a chat commmand to complete"
      },
      {	NULL }
};

PyTypeObject twopence_ChatType = {
	PyObject_HEAD_INIT(NULL)

	.tp_name	= "twopence.Chat",
	.tp_basicsize	= sizeof(twopence_Chat),
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "Twopence status",

	.tp_methods	= twopence_chatMethods,
	.tp_init	= (initproc) Chat_init,
	.tp_new		= Chat_new,
	.tp_dealloc	= (destructor) Chat_dealloc,

	.tp_getattr	= (getattrfunc) Chat_getattr,
};

/*
 * Constructor: allocate empty Chat object, and set its members.
 */
static PyObject *
Chat_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	twopence_Chat *self;

	self = (twopence_Chat *) type->tp_alloc(type, 0);
	if (self == NULL)
		return NULL;

	/* init members */
	self->pid = 0;
	self->target = NULL;
	self->command = NULL;
	memset(&self->chat, 0, sizeof(self->chat));

	return (PyObject *)self;
}

/*
 * Initialize the status object
 */
static int
Chat_init(twopence_Chat *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		NULL
	};

	if (args == Py_None)
		return 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist))
		return -1;

	return 0;
}

/*
 * Destructor: clean any state inside the Chat object
 */
static void
Chat_dealloc(twopence_Chat *self)
{
	twopence_chat_destroy(&self->chat);
	drop_object((PyObject **) &self->target);
	drop_object((PyObject **) &self->command);
}

int
Chat_Check(PyObject *self)
{
	return PyType_IsSubtype(Py_TYPE(self), &twopence_ChatType);
}

static PyObject *
Chat_getattr(twopence_Chat *self, char *name)
{
	if (!strcmp(name, "commandline")
	 || !strcmp(name, "timeout")
	 || !strcmp(name, "user")) {
		if (self->command == NULL) {
			PyErr_Format(PyExc_AttributeError, "No command object when querying attribute %s", name);
			return NULL;
		}
		return self->command->ob_type->tp_getattr((PyObject *) self->command, name);
	}

	if (!strcmp(name, "consumed")) {
		PyObject *buffer = twopence_callType(&PyByteArray_Type, NULL, NULL);

		twopence_AppendBuffer(buffer, &self->chat.consumed);
		return buffer;
	}
	if (!strcmp(name, "found")) {
		if (self->chat.found == NULL) {
			Py_INCREF(Py_None);
			return Py_None;
		}

		return PyString_FromString(self->chat.found);
	}

	return Py_FindMethod(twopence_chatMethods, (PyObject *) self, name);
}

/*
 * Check if all strings passed into chat_expect() are valid
 */
static bool
Chat_expect_set_strings(twopence_expect_t *e, PyObject *expectObj)
{
	unsigned int k;

	if (PyString_Check(expectObj)) {
		e->strings[0] = PyString_AsString(expectObj);
		e->nstrings = 1;
	} else
	if (PySequence_Check(expectObj)) {
		unsigned int count = PySequence_Size(expectObj);

		if (count == 0) {
			PyErr_SetString(PyExc_TypeError, "chat.expect(): empty <expect> tuple");
			return false;
		}
		if (count > TWOPENCE_EXPECT_MAX_STRINGS) {
			PyErr_SetString(PyExc_TypeError, "chat.expect(): too many elements in <expect> argument");
			return false;
		}

		for (k = 0; k < count; ++k) {
			PyObject *item = PySequence_GetItem(expectObj, k);

			if (!PyString_Check(item))
				goto bad_string;
			e->strings[k] = PyString_AsString(item);
		}
		e->nstrings = count;
	} else {
		PyErr_SetString(PyExc_TypeError, "chat.expect(): invalid <expect> argument");
		return false;
	}

	if (e->nstrings == 0)
		return false;
	for (k = 0; k < e->nstrings; ++k) {
		const char *s = e->strings[k];

		if (s == NULL || s[0] == '\0')
			goto bad_string;
	}

	return true;

bad_string:
	PyErr_SetString(PyExc_TypeError, "chat.expect(): bad string in <expect> argument");
	return false;
}

/*
 * Wait for command to produce a given output
 */
static PyObject *
Chat_expect(PyObject *self, PyObject *args, PyObject *kwds)
{
	twopence_Chat *chatObject = (twopence_Chat *) self;
	static char *kwlist[] = {
		"expect",
		"timeout",
		NULL
	};
	PyObject *expectObj, *result = NULL;
	twopence_expect_t expect;
	int timeout = -1;
	int rv;

	memset(&expect, 0, sizeof(expect));

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i", kwlist, &expectObj, &timeout))
		return NULL;

	if (chatObject->target == NULL) {
		PyErr_SetString(PyExc_TypeError, "chat.expect(): invalid chat object (no target attr set)");
		return NULL;
	}

	expect.timeout = timeout;
	if (!Chat_expect_set_strings(&expect, expectObj))
		return NULL;

	rv = twopence_chat_expect(chatObject->target->handle, &chatObject->chat, &expect);
	if (rv <= 0) {
		/* There are a number of reasons for getting here:
		 *  - command exited without producing further output (nbytes is 0 in this case)
		 *  - timed out waiting for output
		 *  - transaction failed for some reason
		 *  - transport errors
		 */
		result = Py_None;
	} else {
		result = Py_True;
	}

	Py_INCREF(result);
	return result;
}

static PyObject *
Chat_send(PyObject *self, PyObject *args, PyObject *kwds)
{
	twopence_Chat *chatObject = (twopence_Chat *) self;
	static char *kwlist[] = {
		"string",
		NULL
	};
	char *string;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &string))
		return NULL;

	if (chatObject->target == NULL) {
		PyErr_SetString(PyExc_TypeError, "chat.expect(): invalid chat object (no target attr set)");
		return NULL;
	}

	twopence_chat_puts(chatObject->target->handle, &chatObject->chat, string);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
Chat_recvline(PyObject *self, PyObject *args, PyObject *kwds)
{
	twopence_Chat *chatObject = (twopence_Chat *) self;
	static char *kwlist[] = {
		"timeout",
		NULL
	};
	int timeout = -1;
	char buffer[512];

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &timeout))
		return NULL;

	if (chatObject->target == NULL) {
		PyErr_SetString(PyExc_TypeError, "chat.expect(): invalid chat object (no target attr set)");
		return NULL;
	}

	if (!twopence_chat_gets(chatObject->target->handle, &chatObject->chat, buffer, sizeof(buffer), timeout)) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	return PyString_FromString(buffer);
}

static PyObject *
Chat_wait(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		NULL
	};
	twopence_Chat *chatObject = (twopence_Chat *) self;
	PyObject *result;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist))
		return NULL;

	if (chatObject->target == NULL) {
		PyErr_SetString(PyExc_TypeError, "chat.expect(): invalid chat object (no target attr set)");
		return NULL;
	}
	if (chatObject->pid == 0) {
		PyErr_SetString(PyExc_TypeError, "chat.expect(): invalid chat object (no pid attr set)");
		return NULL;
	}

	result = Target_wait_common(chatObject->target, chatObject->pid);
	if (result != NULL)
		chatObject->pid = 0;

	return result;
}

