from ansys.geometry import Geometry

def vulnerable_start_program():
    geometry_service = Geometry()
    geometry_service._start_program()

vulnerable_start_program()