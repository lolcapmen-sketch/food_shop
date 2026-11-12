// Единственное место, где описаны адреса API. Сервер отдаёт и страницы, и API с одного адреса,
// поэтому API_URL пустой (запросы идут на тот же хост) и CORS не нужен.
export const API_URL = '';

export const ENDPOINTS = {
  login:        '/api/auth/login',                // POST {email, password} -> {token, user}
  register:     '/api/auth/register',             // POST {name, email, password, phone?, address?} -> {token, user}
  products:     '/api/products',                  // GET -> [{id, name, description, price}]
  staffLogin:   '/api/auth/staff/login',          // POST {email, password} -> {token, user:{role,name}}
  me:           '/api/users/me',                  // GET / PUT / DELETE
  suggestRecipe:'/api/recipes/suggestions',       // POST {title, description, ingredients, steps}
  managerOrders:'/api/manager/orders',            // GET
  managerStatus:(id) => `/api/manager/orders/${id}/status`, // PATCH {status}
  cookOrders:   '/api/cook/orders/active',        // GET -> заказы с рецептами
  courierOrders:'/api/courier/orders',            // GET -> заказы в доставке
  courierDone:  (id) => `/api/courier/orders/${id}/done`, // PATCH
  createOrder:  '/api/orders',                    // POST {items, deliveryAddress, deliveryLat, deliveryLng}
};

// Куда вести персонал после входа
export const ROLE_REDIRECT = {
  admin:   'manager.html',   // отдельной страницы администратора нет — открывается раздел менеджера
  courier: 'courier.html',
  manager: 'manager.html',
  cook:    'cook.html',
};

export const STAFF_LOGIN_PAGE = 'staff-login.html';
export const CUSTOMER_LOGIN_PAGE = 'index.html'; // страница магазина, где пользователь входит
export const CART_KEY = 'cart';                   // [{id, name, price, quantity}]
export const ORDER_STATUSES = {
  new: 'Новый', confirmed: 'Подтверждён', cooking: 'Готовится',
  delivering: 'В доставке', done: 'Выполнен', cancelled: 'Отменён',
};
