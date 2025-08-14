from ansys.geometry import Geometry

def safe_start_program():
    geometry_service = Geometry()
    geometry_service.start_safe_program()

safe_start_program()