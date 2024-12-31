import reflex as rx
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class Key(rx.Model, table=True):
    type: str
    value: str

class User(rx.Model, table=True):
    email: str
    password: str

def get_key():
    print("Initializing keys...")
    with rx.session() as session:
        keys = session.exec(Key.select()).all()
    if not keys:
        keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        State.private_key = keys.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
        State.public_key = keys.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        with rx.session() as session:
            session.add(
                Key(
                    type="private_key", value=State.private_key
                )
            )
            session.add(
                Key(
                    type="public_key", value=State.public_key
                )
            )
            session.commit()
            print("Initialized keys.")

class State(rx.State):
    logging_in: bool = False
    user: User | None = None
    private_key: str = ""
    public_key: str = ""
    login_value: str = rx.Cookie(name="login-value", path="/", max_age=60*60*24*30, secure=False, same_site="strict")

    def log_in(self, form_data: dict):
        print("function was called")
        yield rx.toast.info("Logging in...")
        with rx.session() as session:
            self.user = session.exec(
                User.select().where(
                    (User.email == form_data["email"]) &
                    (User.password == form_data["password"])
                )
            ).first()
        if self.user:
            public_key = serialization.load_pem_public_key(self.public_key.encode())
            self.login_value = public_key.encrypt(
                f"email:{form_data["email"].encode()};password:{form_data["password"].encode()}",
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return rx.toast.success("Log in successful.")
        else:
            return rx.toast.error("Log in failed: Incorrect Email or Password!")
        

def login() -> rx.Component:
    return rx.box(
        rx.flex(
            rx.box(
                rx.flex(
                    rx.heading(
                        "Welcome Back,",
                        as_="h6",
                    ),
                    rx.text(
                        "Please login with your credentials!",
                        opacity="0.5",
                        spacing="1", # uh disxord
                    ),
                    rx.form(
                        rx.form.field(
                            rx.form.label("Email"),
                            rx.input(
                                placeholder="atherius@cool.man",
                                name="email",
                                background_color="transparent",
                                style={"& input::placeholder": {"color": "gray"}},
                                color="white",
                            ),
                            rx.form.label("Password"),
                            rx.input(
                                placeholder="******",
                                name="password",
                                type="password",
                                background_color="transparent",
                                style={"& input::placeholder": {"color": "gray"}},
                                color="white",
                            ),
                            rx.button(
                                "Log in",
                                type="submit",
                                margin_top="1rem",
                                background_color="#5D3EE5",
                            ),
                            rx.center(
                                rx.text("No account?"),
                                rx.link("Register", href="/register"),
                                spacing="2",
                                margin_top="1rem",
                            ),
                        ),
                        on_submit=State.log_in,
                    ),
                    direction="column",
                ),
                color="white",
                background_color="#1D1C22", 
                border_radius="8px",
                padding="2rem",
                width="400px",
                min_width="400px"
            ),
            direction="column",
            justify="center",
            align="center",
            overflow="auto",
            width="100%",
            height="100%",
        ),
        background_color="#0E0E12",
        width="100%",
        height="100vh",
    )

app = rx.App(state=State)
app.add_page(login, route="/login")
app.register_lifespan_task(get_key)