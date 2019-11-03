<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
  if (request.getParameter("logoff") != null) {
    session.invalidate();
    response.sendRedirect("login.jsp");
    return;
  }
%>

<html>
  <head>
      <meta http-equiv="content-type" content="text/html; charset=UTF-8">
      <title>Home Page</title>
  </head>
<body>


<h3>Módulo Ventas</h3></td>
<p><a href="ventas/gestion_clientes.jsp">Operación: gestionar clientes</a></p>
<p><a href="ventas/gestion_presupuestos.jsp">Operación: gestionar presupuestos</a></p>
<p><a href="ventas/gestion_facturas.jsp">Operación: gestionar facturas</a></p>

<h3>Módulo Compras</h3></td>
<p><a href="compras/gestion_proveedores.jsp">Operación: gestionar proveedores</a></p>
<p><a href="compras/gestion_compras.jsp">Operación: gestionar compras</a></p>
<p><a href="compras/autorizar_compras.jsp">Operación: autorizar compras</a></p>


<h3>Módulo Nóminas</h3></td>
<p><a href="nominas/gestion_trabajadores.jsp">Operación: gestionar trabajadores</a></p>
<p><a href="nominas/gestion_nominas.jsp">Operación: gestionar nóminas</a></p>


Cerrar sesión
<a href='<%= response.encodeURL("../index.jsp?logoff=true") %>'>click acá</a>.

</body>
</html>
