import ctypes

   def get_array_value(index_str: str, arr: List[ctypes.c_int]) -> Optional[int]:
       ...
       index = int(index_str)
       if not ctypes.c_int.in_range(index):
           print("Error: Index is outside the valid range for a signed integer.", file=sys.stderr)
           return None
       ...

