from tuple_space import PyTuple, PyTupleSpace

# Create a tuple space
ts = PyTupleSpace("server01")

# Create a tuple with 2 elements
t = PyTuple(2)
t.set_element(0, "int", 42)
t.set_element(1, "string", "hello")

# Print the tuple
print("Original tuple:")
t.print()

# Put the tuple into the tuple space
tuple_id = ts.put(t)
print(f"Tuple ID: {tuple_id}")

# Retrieve the tuple by ID
retrieved = ts.get(tuple_id)
print("Retrieved tuple:")
retrieved.print()

# Test remove
removed = ts.remove(tuple_id)
print(f"Removed: {removed}")

# Try to get it again (should return None)
retrieved_again = ts.get(tuple_id)
print(f"Retrieved after remove: {retrieved_again}")
