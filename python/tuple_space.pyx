# tuple_space.pyx
cdef extern from "tuple.h":
    ctypedef enum ElementTag:
        ELEMENT_INT
        ELEMENT_FLOAT
        ELEMENT_STRING
        ELEMENT_TUPLE
        ELEMENT_INT_ARRAY
        ELEMENT_FLOAT_ARRAY
        ELEMENT_WILDCARD

    ctypedef struct String:
        const char *ptr
        size_t len

    ctypedef struct IntArray:
        const int64_t *ptr
        size_t len

    ctypedef struct FloatArray:
        const double *ptr
        size_t len

    ctypedef struct Tuple:
        uint64_t id
        char space_id[32]
        char label[32]
        Element *elements
        size_t elements_len
        uint64_t client_id
        uint64_t resource_id
        uint64_t request_id
        int64_t timestamp
        TupleState state

    ctypedef union ElementData:
        int64_t Int
        double Float
        String String
        Tuple *Tuple
        IntArray IntArray
        FloatArray FloatArray

    ctypedef struct Element:
        ElementTag tag
        ElementData data

    ctypedef enum TupleState:
        STATE_NEW
        STATE_TAKEN
        STATE_DONE
        STATE_RET

    uint64_t generate_tuple_id()
    Tuple *tuple_init(size_t elements_len)
    void tuple_set_element(Tuple *self, size_t index, ElementTag tag, ElementData data)
    void tuple_deinit(Tuple *self)
    Tuple *tuple_copy(const Tuple *src)
    int tuple_serialize(const Tuple *self, uint8_t **buffer, size_t *len)
    Tuple *tuple_deserialize(uint8_t **buffer, size_t len)
    void tuple_print(const Tuple *self, FILE *writer)

cdef extern from "tuple_space.h":
    ctypedef struct TupleSpace:
        char space_id[32]
        void *entries  # GHashTable *entries (opaque pointer in Cython)
        void *db       # sqlite3 *db (opaque pointer)
        pthread_rwlock_t rwlock
        void *server_key  # EVP_PKEY *server_key (opaque pointer)

    TupleSpace *tuple_space_init(const char *server_id)
    void tuple_space_deinit(TupleSpace *self)
    int tuple_space_put(TupleSpace *self, Tuple *t, uint64_t *out_id)
    Tuple *tuple_space_get(TupleSpace *self, uint64_t id)
    bint tuple_space_remove(TupleSpace *self, uint64_t id)
    Tuple *tuple_space_take(TupleSpace *self, Tuple *t)
    Tuple *tuple_space_read(TupleSpace *self, Tuple *t)

# Python wrapper class for Tuple
cdef class PyTuple:
    cdef Tuple *c_tuple

    def __cinit__(self, size_t elements_len):
        self.c_tuple = tuple_init(elements_len)
        if self.c_tuple == NULL:
            raise MemoryError("Failed to initialize Tuple")

    def __dealloc__(self):
        if self.c_tuple != NULL:
            tuple_deinit(self.c_tuple)
            self.c_tuple = NULL

    @property
    def id(self):
        return self.c_tuple.id

    def set_element(self, size_t index, tag, data):
        cdef ElementData ed
        if tag == "int":
            ed.Int = data
            tuple_set_element(self.c_tuple, index, ELEMENT_INT, ed)
        elif tag == "float":
            ed.Float = data
            tuple_set_element(self.c_tuple, index, ELEMENT_FLOAT, ed)
        elif tag == "string":
            cdef bytes b_data = data.encode('utf-8')
            ed.String.ptr = b_data
            ed.String.len = len(b_data)
            tuple_set_element(self.c_tuple, index, ELEMENT_STRING, ed)
        # Add more types as needed (e.g., arrays, nested tuples)

    def print(self):
        tuple_print(self.c_tuple, stdout)

# Python wrapper class for TupleSpace
cdef class PyTupleSpace:
    cdef TupleSpace *c_space

    def __cinit__(self, server_id: str):
        cdef bytes b_server_id = server_id.encode('utf-8')
        self.c_space = tuple_space_init(b_server_id)
        if self.c_space == NULL:
            raise MemoryError("Failed to initialize TupleSpace")

    def __dealloc__(self):
        if self.c_space != NULL:
            tuple_space_deinit(self.c_space)
            self.c_space = NULL

    def put(self, PyTuple t):
        cdef uint64_t out_id
        cdef int result = tuple_space_put(self.c_space, t.c_tuple, &out_id)
        if result != 0:
            raise RuntimeError("Failed to put tuple")
        return out_id

    def get(self, uint64_t id):
        cdef Tuple *t = tuple_space_get(self.c_space, id)
        if t == NULL:
            return None
        cdef PyTuple py_t = PyTuple(t.elements_len)
        py_t.c_tuple = tuple_copy(t)  # Copy to manage memory independently
        return py_t

    def remove(self, uint64_t id):
        return tuple_space_remove(self.c_space, id)

    def take(self, PyTuple t):
        cdef Tuple *result = tuple_space_take(self.c_space, t.c_tuple)
        if result == NULL:
            return None
        cdef PyTuple py_t = PyTuple(result.elements_len)
        py_t.c_tuple = tuple_copy(result)
        return py_t

    def read(self, PyTuple t):
        cdef Tuple *result = tuple_space_read(self.c_space, t.c_tuple)
        if result == NULL:
            return None
        cdef PyTuple py_t = PyTuple(result.elements_len)
        py_t.c_tuple = tuple_copy(result)
        return py_t