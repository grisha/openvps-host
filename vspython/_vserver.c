/*
 * Copyright 2005 OpenHosting, Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You
 * may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * $Id: _vserver.c,v 1.4 2006/07/08 19:21:24 grisha Exp $
 *
 */

#include <Python.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <vserver.h>

#include <stdio.h>


// vc_syscall


static PyObject * 
_vs_vc_get_version(PyObject *self)
{
  return PyInt_FromLong(vc_get_version());
}

/* static PyObject *  */
/* _vs_vc_new_s_context(PyObject *self, PyObject *argv) */
/* { */

/*   xid_t xid; */
/*   int remove_cap, flags; */

/*   if (! PyArg_ParseTuple(argv, "iii", &xid, &remove_cap, &flags)) */
/*     return NULL; */


/*   xid = vc_new_s_context(xid, remove_cap, flags); */
/*   if (xid == VC_NOCTX) { */
/*     return PyErr_SetFromErrno(PyExc_OSError); */
/*   } */

/*   return PyInt_FromLong(xid); */
/* } */

static PyObject * 
_vs_vc_get_iattr(PyObject *self, PyObject *argv)
{

  char * name;
  xid_t xid;
  uint32_t flags, mask;


  if (! PyArg_ParseTuple(argv, "s", &name))
    return NULL;

  if (vc_get_iattr(name, &xid, &flags, &mask) == -1)
    return PyErr_SetFromErrnoWithFilename(PyExc_IOError, name);

  return Py_BuildValue("iii", xid, flags, mask);

}

static PyObject * 
_vs_vc_set_iattr(PyObject *self, PyObject *argv)
{

  char * name;
  xid_t xid;
  uint32_t flags, mask;

  if (! PyArg_ParseTuple(argv, "siii", &name, &xid, &flags, &mask))
    return NULL;

  if (vc_set_iattr(name, xid, flags, mask) == -1)
    return PyErr_SetFromErrnoWithFilename(PyExc_IOError, name);

  Py_INCREF(Py_None);
  return Py_None;

}

struct PyMethodDef _vs_module_methods[] = {
    {"vc_get_version",     (PyCFunction) _vs_vc_get_version,   METH_NOARGS},
    //    {"vc_new_s_context",   (PyCFunction) _vs_vc_new_s_context, METH_VARARGS},
    {"vc_get_iattr",       (PyCFunction) _vs_vc_get_iattr,     METH_VARARGS},
    {"vc_set_iattr",       (PyCFunction) _vs_vc_set_iattr,     METH_VARARGS},
    {NULL, NULL}
};

void init_vserver(void)
{
    Py_InitModule("_vserver", _vs_module_methods);
}
