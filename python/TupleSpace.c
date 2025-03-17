#define PY_SSIZE_T_CLEAN
#include <python3.12/Python.h>
#include "tuple_space.h"

typedef struct
{
    PyObject_HEAD TupleSpace *ts;
} TupleSpaceObject;

static PyObject *TupleSpace_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    TupleSpaceObject *self = (TupleSpaceObject *)type->tp_alloc(type, 0);
    if (self)
    {
        self->ts = tuplespace_create();
        if (!self->ts)
        {
            Py_DECREF(self);
            return NULL;
        }
    }
    return (PyObject *)self;
}

// Frees the TupleSpaceObject and its underlying Zig TupleSpace.
static void TupleSpace_dealloc(TupleSpaceObject *self)
{
    if (self->ts)
    {
        tuplespace_destroy(self->ts);
        self->ts = NULL; // Prevent double-free in case of buggy reuse
    }
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *TupleSpace_put_int(TupleSpaceObject *self, PyObject *args)
{
    long value;
    if (!PyArg_ParseTuple(args, "l", &value))
    {
        return NULL;
    }
    if (tuplespace_put_int(self->ts, value) != 0)
    {
        PyErr_SetString(PyExc_RuntimeError, "Failed to put int");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *TupleSpace_get_int(TupleSpaceObject *self, PyObject *args)
{
    long value;
    if (!PyArg_ParseTuple(args, "l", &value))
    {
        return NULL;
    }
    if (tuplespace_get_int(self->ts, value) == 0)
    {
        Py_RETURN_TRUE; // Found
    }
    Py_RETURN_FALSE; // Not found
}

static PyObject *TupleSpace_take_int(TupleSpaceObject *self, PyObject *args)
{
    long value;
    int64_t out_value;
    if (!PyArg_ParseTuple(args, "l", &value))
    {
        return NULL;
    }
    if (tuplespace_take_int(self->ts, value, &out_value) == 0)
    {
        return PyLong_FromLongLong(out_value); // Return taken value
    }
    Py_RETURN_NONE; // Not found
}

static PyObject *TupleSpace_put_string(TupleSpaceObject *self, PyObject *args)
{
    const char *value;
    Py_ssize_t len;
    if (!PyArg_ParseTuple(args, "s#", &value, &len))
    {
        return NULL;
    }
    if (len < 0)
    {
        PyErr_SetString(PyExc_ValueError, "String length cannot be negative");
        return NULL;
    }
    if (tuplespace_put_string(self->ts, value, len) != 0)
    {
        PyErr_SetString(PyExc_RuntimeError, "Failed to put string");
        return NULL;
    }
    Py_RETURN_NONE;
}

// Takes a string from the tuple space, returning it as a Python string or None if not found.
// - value: The string template to match.
// Returns a Python string object with the taken value, freeing the Zig-allocated pointer responsibly.
static PyObject *TupleSpace_take_string(TupleSpaceObject *self, PyObject *args)
{
    const char *value;
    Py_ssize_t len;
    if (!PyArg_ParseTuple(args, "s#", &value, &len))
    {
        return NULL;
    }
    char *out_ptr;
    size_t out_len;
    if (tuplespace_take_string(self->ts, value, len, &out_ptr, &out_len) == 0)
    {
        PyObject *result = Py_BuildValue("s#", out_ptr, out_len);
        free(out_ptr); // Zig allocated, we free after Python takes ownership
        return result;
    }
    Py_RETURN_NONE;
}

static PyObject *TupleSpace_save(TupleSpaceObject *self, PyObject *args)
{
    const char *path;
    if (!PyArg_ParseTuple(args, "s", &path))
    {
        return NULL;
    }
    if (tuplespace_save(self->ts, path) != 0)
    {
        PyErr_SetString(PyExc_IOError, "Failed to save tuple space");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyMethodDef TupleSpace_methods[] = {
    {"put_int", (PyCFunction)TupleSpace_put_int, METH_VARARGS, "Put an integer into the tuple space"},
    {"get_int", (PyCFunction)TupleSpace_get_int, METH_VARARGS, "Check if an integer exists in the tuple space"},
    {"take_int", (PyCFunction)TupleSpace_take_int, METH_VARARGS, "Take an integer from the tuple space"},
    {"put_string", (PyCFunction)TupleSpace_put_string, METH_VARARGS, "Put a string into the tuple space"},
    {"take_string", (PyCFunction)TupleSpace_take_string, METH_VARARGS, "Take a string from the tuple space"},
    {"save", (PyCFunction)TupleSpace_save, METH_VARARGS, "Save tuple space to a file"},
    {NULL, NULL, 0, NULL}};

static PyTypeObject TupleSpaceType = {
    PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name = "TupleSpace.TupleSpace",
    .tp_doc = "TupleSpace object",
    .tp_basicsize = sizeof(TupleSpaceObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = TupleSpace_new,
    .tp_dealloc = (destructor)TupleSpace_dealloc,
    .tp_methods = TupleSpace_methods,
};

static PyModuleDef TupleSpacemodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "TupleSpace",
    .m_doc = "A Python module for interacting with a Zig TupleSpace",
    .m_size = -1,
};

PyMODINIT_FUNC PyInit_TupleSpace(void)
{
    PyObject *m;
    if (PyType_Ready(&TupleSpaceType) < 0)
        return NULL;

    m = PyModule_Create(&TupleSpacemodule);
    if (m == NULL)
        return NULL;

    Py_INCREF(&TupleSpaceType);
    if (PyModule_AddObject(m, "TupleSpace", (PyObject *)&TupleSpaceType) < 0)
    {
        Py_DECREF(&TupleSpaceType);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}