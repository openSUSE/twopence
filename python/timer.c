/*
Twopence python bindings - class Timer

Copyright (C) 2016 SUSE

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

static void		Timer_dealloc(twopence_Timer *self);
static PyObject *	Timer_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static int		Timer_init(twopence_Timer *self, PyObject *args, PyObject *kwds);
static PyObject *	Timer_getattr(twopence_Timer *self, char *name);
static int		Timer_setattr(twopence_Timer *self, char *name, PyObject *);
static PyObject *	Timer_pause(twopence_Timer *, PyObject *, PyObject *);
static PyObject *	Timer_unpause(twopence_Timer *, PyObject *, PyObject *);
static PyObject *	Timer_cancel(twopence_Timer *, PyObject *, PyObject *);
static void		__Timer_callback(twopence_timer_t *t, void *user_data);

/*
 * Define the python bindings of class "Timer"
 * Normally, you do not create Timer objects yourself;
 * Usually, these are created as the return value of Target.addtimer()
 */
static PyMethodDef twopence_timerMethods[] = {
      {	"cancel", (PyCFunction) Timer_cancel, METH_VARARGS | METH_KEYWORDS,
	"Cancel the timer"
      },
      {	"pause", (PyCFunction) Timer_pause, METH_VARARGS | METH_KEYWORDS,
	"Pause the timer"
      },
      {	"unpause", (PyCFunction) Timer_unpause, METH_VARARGS | METH_KEYWORDS,
	"Unpause the timer"
      },
      {	NULL }
};

PyTypeObject twopence_TimerType = {
	PyObject_HEAD_INIT(NULL)

	.tp_name	= "twopence.Timer",
	.tp_basicsize	= sizeof(twopence_Timer),
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "Twopence timer",

	.tp_methods	= twopence_timerMethods,
	.tp_init	= (initproc) Timer_init,
	.tp_new		= Timer_new,
	.tp_dealloc	= (destructor) Timer_dealloc,

	.tp_getattr	= (getattrfunc) Timer_getattr,
	.tp_setattr	= (setattrfunc) Timer_setattr,
};

/*
 * Constructor: allocate empty Timer object, and set its members.
 */
static PyObject *
Timer_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	twopence_Timer *self;

	self = (twopence_Timer *) type->tp_alloc(type, 0);
	if (self == NULL)
		return NULL;

	/* init members */
	self->timer = NULL;
	self->callback = NULL;

	return (PyObject *)self;
}

/*
 * Initialize the status object
 */
static int
Timer_init(twopence_Timer *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"timeout",
		"callback",
		NULL
	};
	PyObject *callbackObj = NULL;
	twopence_timer_t *timer;
	double timeout;
	int rc;


	if (args == Py_None)
		return 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "d|O", kwlist, &timeout, &callbackObj))
		return -1;

	if (timeout <= 0) {
		/* FIXME: raise ValueError exception */
		return -1;
	}

	if ((rc = twopence_timer_create(timeout * 1000, &timer)) < 0) {
		twopence_Exception("failed to create timer", rc);
		return -1;
	}

	twopence_timer_hold(timer);
	self->timer = timer;

	if (callbackObj == NULL)
		assign_object(&self->callback, Py_None);
	else
		assign_object(&self->callback, callbackObj);

	twopence_timer_set_callback(timer, __Timer_callback, self);

	return 0;
}

/*
 * This callback gets invoked from the lower-level twopence library
 * when the timer fires.
 */
static void
__Timer_callback(twopence_timer_t *t, void *user_data)
{
	twopence_Timer *timerObj = (twopence_Timer *) user_data;
	PyObject *v;

	if (timerObj->callback == NULL || timerObj->callback == Py_None) {
		twopence_debug("Timer %u fired; no python callback set", t->id);
		return;
	}

	twopence_debug("Timer %u fired; invoking python callback", t->id);
	v = twopence_callObject(timerObj->callback, NULL, NULL);
	if (v == NULL) {
		twopence_log_error("Exception in twopence.Timer callback");
	} else {
		/* We don't care what it returned, we just need to dispose of it */
		Py_DECREF(v);
	}
}

/*
 * Destructor: clean any state inside the Timer object
 */
static void
Timer_dealloc(twopence_Timer *self)
{
	if (self->timer)
		twopence_timer_release(self->timer);
	self->timer = NULL;

	drop_object(&self->callback);
}

int
Timer_Check(PyObject *self)
{
	return PyType_IsSubtype(Py_TYPE(self), &twopence_TimerType);
}

static twopence_timer_t *
Timer_handle(twopence_Timer *self)
{
	if (self->timer)
		return self->timer;

	PyErr_SetString(PyExc_ValueError, "Timer object without handle");
	return NULL;
}

const char *
Timer_state2name(int state)
{
	switch (state) {
	case TWOPENCE_TIMER_STATE_ACTIVE:
		return "active";
	case TWOPENCE_TIMER_STATE_PAUSED:
		return "paused";
	case TWOPENCE_TIMER_STATE_CANCELLED:
		return "cancelled";
	case TWOPENCE_TIMER_STATE_EXPIRED:
	case TWOPENCE_TIMER_STATE_DEAD:
		return "expired";
	}
	return "unknown";
}

static PyObject *
Timer_getattr(twopence_Timer *self, char *name)
{
	if (!strcmp(name, "callback")
	 || !strcmp(name, "state")
	 || !strcmp(name, "remaining")
	 || !strcmp(name, "id")) {
		twopence_timer_t *timer;

		if (!(timer = Timer_handle(self)))
			return NULL;

		if (!strcmp(name, "callback")) {
			Py_INCREF(self->callback);
			return self->callback;
		}
		if (!strcmp(name, "state"))
			return PyString_FromString(Timer_state2name(timer->state));
		if (!strcmp(name, "id"))
			return PyInt_FromLong(timer->id);
		if (!strcmp(name, "remaining"))
			return PyFloat_FromDouble(twopence_timer_remaining(timer) * 1e-3);
	}

	return Py_FindMethod(twopence_timerMethods, (PyObject *) self, name);
}

static int
Timer_setattr(twopence_Timer *self, char *name, PyObject *v)
{
	twopence_timer_t *timer;

	if (!(timer = Timer_handle(self)))
		return -1;

	if (timer->state != TWOPENCE_TIMER_STATE_ACTIVE
	 && timer->state != TWOPENCE_TIMER_STATE_PAUSED)
		goto bad_expired;

	if (!strcmp(name, "callback")) {
		assign_object(&self->callback, v);
		return 0;
	}

	(void) PyErr_Format(PyExc_AttributeError, "Unknown attribute: %s", name);
	return -1;

bad_expired:
	(void) PyErr_Format(PyExc_AttributeError, "Cannot set attribute: %s in expired timer", name);
	return -1;
}

static PyObject *
Timer_cancel(twopence_Timer *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		NULL
	};
	twopence_timer_t *timer;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist))
		return NULL;

	if (!(timer = Timer_handle(self)))
		return NULL;

	twopence_timer_cancel(timer);
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
Timer_pause(twopence_Timer *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		NULL
	};
	twopence_timer_t *timer;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist))
		return NULL;

	if (!(timer = Timer_handle(self)))
		return NULL;

	twopence_timer_pause(timer);
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
Timer_unpause(twopence_Timer *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		NULL
	};
	twopence_timer_t *timer;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist))
		return NULL;

	if (!(timer = Timer_handle(self)))
		return NULL;

	twopence_timer_unpause(timer);
	Py_INCREF(Py_None);
	return Py_None;
}
