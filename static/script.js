let cart = [];

function fetchProducts() {
    fetch('/products')
    .then(res => res.json())
    .then(data => {
        let list = document.getElementById('product-list');
        list.innerHTML = '';
        data.forEach(product => {
            let div = document.createElement('div');
            div.className = 'product';
            div.innerHTML = `
                <h3>${product.name}</h3>
                <p>₹${product.price}</p>
                <button onclick="addToCart('${product.name}', ${product.price})">Add</button>
            `;
            list.appendChild(div);
        });
    });
}

function addToCart(name, price) {
    cart.push({name, price});
    displayCart();
}

function displayCart() {
    let cartDiv = document.getElementById('cart');
    cartDiv.innerHTML = '';
    cart.forEach(item => {
        let div = document.createElement('div');
        div.textContent = `${item.name} - ₹${item.price}`;
        cartDiv.appendChild(div);
    });
}

function placeOrder() {
    fetch('/order', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({items: cart})
    })
    .then(res => res.json())
    .then(data => {
        alert(data.message);
        cart = [];
        displayCart();
    });
}

window.onload = fetchProducts;
