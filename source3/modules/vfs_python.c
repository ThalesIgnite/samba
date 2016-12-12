#include "vfs_python.h"
#include "python2.7/Python.h"
#define vfs_python_init samba_init_module


int python_connect(vfs_handle_struct *handle,
                   char *service,
                   char *user)
{
    int success = 1;
    
    struct PyObject *py_func = get_func(handle, "connect");
    if (py_func != NULL)
    {
        PyObject *py_ret = PyObject_CallFunction(py_func, "ss", service, user);
        success = PyObject_IsTrue(py_ret);
        Py_DECREF(py_ret);
        Py_DECREF(py_func);
    }
    
    if (success == 1)
    {
        return SMB_VFS_NEXT_CONNECT(handle, service, user);
    }
    else
    {
        return -1;
    }
}

void python_disconnect(vfs_handle_struct *handle)
{
    SMB_VFS_NEXT_DISCONNECT(handle);
}


int python_mkdir(vfs_handle_struct *handle,
                 const char *path,
                 mode_t mode)
{
    int success = 1;
    
    struct PyObject *py_func = get_func(handle, "mkdir");
    if (py_func != NULL)
    {
        struct PyObject *py_ret = PyObject_CallFunction(py_func, "s", path);
        success = PyObject_IsTrue(py_ret);
        Py_DECREF(py_ret);
        Py_DECREF(py_func);
    }
    
    if (success == 1)
    {
        return SMB_VFS_NEXT_MKDIR(handle, path, mode);
    }
    else
    {
        return -1;
    }
}

int python_rmdir(vfs_handle_struct *handle, const char *path)
{
    int success = 1;
    
    struct PyObject *py_func = get_func(handle, "rmdir");
    if (py_func != NULL)
    {
        PyObject *py_ret = PyObject_CallFunction(py_func, "s", path);
        success = PyObject_IsTrue(py_ret);
        Py_DECREF(py_ret);
        Py_DECREF(py_func);
    }
    
    if (success == 1)
    {
        return SMB_VFS_NEXT_RMDIR(handle, path);
    }
    else
    {
        return -1;
    }
}

NTSTATUS python_create_file(struct vfs_handle_struct *handle,
                            struct smb_request *req,
                            uint16_t root_dir_fid,
                            struct smb_filename *smb_fname,
                            uint32_t access_mask,
                            uint32_t share_access,
                            uint32_t create_disposition,
                            uint32_t create_options,
                            uint32_t file_attributes,
                            uint32_t oplock_request,
                            struct smb2_lease *lease,
                            uint64_t allocation_size,
                            uint32_t private_flags,
                            struct security_descriptor *sd,
                            struct ea_list *ea_list,
                            files_struct **result,
                            int *pinfo,
                            const struct smb2_create_blobs *in_context_blobs,
				     		struct smb2_create_blobs *out_context_blobs)
{
    int success = 1;
    
    PyObject *py_func = get_func(handle, "create_file");
    if (py_func != NULL)
    {
        PyObject *py_ret = PyObject_CallFunction(py_func, "s", smb_fname->base_name);
        success = PyObject_IsTrue(py_ret);
        Py_DECREF(py_ret);
        Py_DECREF(py_func);
    }
    
    if (success == 1)
    {
        return SMB_VFS_NEXT_CREATE_FILE(handle,
                                        req,
                                        root_dir_fid,
                                        smb_fname,
                                        access_mask,
                                        share_access,
                                        create_disposition,
                                        create_options,
                                        file_attributes,
                                        oplock_request,
                                        lease,
                                        allocation_size,
                                        private_flags,
                                        sd,
                                        ea_list,
                                        result,
                                        pinfo,
                                        in_context_blobs,
                                        out_context_blobs);

    }
    else
    {
        return NT_STATUS_UNSUCCESSFUL;
    }
}

int python_rename(vfs_handle_struct *handle,
                  const struct smb_filename *smb_fname_src,
                  const struct smb_filename *smb_fname_dst)
{
    int success = 1;
    
    PyObject *py_func = get_func(handle, "rename");
    if (py_func != NULL)
    {
        PyObject *py_ret = PyObject_CallFunction(py_func,
                                                 "ss",
                                                 smb_fname_src->base_name,
                                                 smb_fname_dst->base_name);
        success = PyObject_IsTrue(py_ret);
        Py_DECREF(py_ret);
        Py_DECREF(py_func);
    }
    
    if (success == 1)
    {
        return SMB_VFS_NEXT_RENAME(handle, smb_fname_src, smb_fname_dst);
    }
    else
    {
        return -1;
    }
}

int python_unlink(vfs_handle_struct *handle,
                  const struct smb_filename *smb_fname)
{
    int success = 1;
    
    PyObject *py_func = get_func(handle, "unlink");
    if (py_func != NULL)
    {
        PyObject *py_ret = PyObject_CallFunction(py_func, "s", smb_fname->base_name);
        success = PyObject_IsTrue(py_ret);
        Py_DECREF(py_ret);
        Py_DECREF(py_func);
    }
    
    if (success == 1)
    {
        return SMB_VFS_NEXT_UNLINK(handle, smb_fname);
    }
    else
    {
        return -1;
    }
}



PyObject *py_handler;
bool always_import = false;


void debug(const char *text)
{
    FILE *fp = fopen("/tmp/samba.log", "a");
    {
        fprintf(fp, "SAMBA (%s): %s\n", getenv("USER"), text);
        fclose(fp);
    }
}

const char *get_conf(vfs_handle_struct *handle, const char *name)
{
    return lp_parm_const_string(SNUM(handle->conn), "python", name, NULL);
}

struct PyObject *get_py_mod(const char *script_path)
{
    PyObject *py_mod;
    PyObject *py_imp_str, *py_imp_handle, *py_imp_dict;
    PyObject *py_imp_load_source, *py_args_tuple;
    
    Py_Initialize();
    
    py_imp_str = PyString_FromString("imp");
    py_imp_handle = PyImport_Import(py_imp_str);
    py_imp_dict = PyModule_GetDict(py_imp_handle);
    py_imp_load_source = PyDict_GetItemString(py_imp_dict, "load_source");
    
    py_args_tuple = PyTuple_New(2);
    PyTuple_SetItem(py_args_tuple, 0, PyString_FromString("handler"));
    PyTuple_SetItem(py_args_tuple, 1, PyString_FromString(script_path));
    
    py_mod = PyObject_CallObject(py_imp_load_source, py_args_tuple);
    
    Py_DECREF(py_args_tuple);
    Py_DECREF(py_imp_str);
    Py_DECREF(py_imp_handle);
    Py_DECREF(py_imp_dict);
    Py_DECREF(py_imp_load_source);
    
    return py_mod;
}

struct PyObject *get_py_func(PyObject *py_mod, const char *func_name)
{
    PyObject *py_func_name = PyString_FromString(func_name);
    PyObject *py_func = PyObject_GetAttr(py_mod, py_func_name);
    Py_DECREF(py_func_name);
    
    if (py_func != NULL)
    {
        if (PyCallable_Check(py_func) == 1)
        {
            return py_func;
        }
    }
    debug("something went wrong get_py_func.");
    return NULL;
}

struct PyObject *get_func(vfs_handle_struct *handle,
                          const char *func_name)
{
    debug("get_func");
    if ((py_handler == NULL) || (always_import == true))
    {
        debug("importing module.");
        const char *script_path = get_conf(handle, "script");
        py_handler = get_py_mod(script_path);
    }
    
    return get_py_func(py_handler, func_name);
}




static struct vfs_fn_pointers vfs_python_fns = {
    .connect_fn = python_connect,
    .disconnect_fn = python_disconnect,
    .mkdir_fn = python_mkdir,
    .rmdir_fn = python_rmdir,
    .create_file_fn = python_create_file,
    .rename_fn = python_rename,
    .unlink_fn = python_unlink
};


NTSTATUS vfs_python_init(void)
{
    return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
                            "python",
                            &vfs_python_fns);
}
