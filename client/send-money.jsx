import React, { useState } from 'react';
import ReactDOM from 'react-dom';

function App() {
  const [senderEmail, setSenderEmail] = useState('');
  const [recipientEmail, setRecipientEmail] = useState('');
  const [amount, setAmount] = useState('');
  const [message, setMessage] = useState('');

  const handleSubmit = (event) => {
    event.preventDefault();
    // Xử lý logic gửi tiền ở đây
    console.log('Submit form with:', senderEmail, recipientEmail, amount, message);
  };

  return (
    <main>
      <header className="site-header">
        {/* Header content here */}
      </header>
      <section className="hero-section d-flex justify-content-center align-items-center">
        <div className="container">
          <div className="row">
            <div className="col-lg-6 col-12 mx-auto">
              <form className="custom-form contact-form" onSubmit={handleSubmit}>
                <h2 className="hero-title text-center mb-4 pb-2">Chuyển tiền</h2>
                <div className="col-lg-6 col-md-6 col-12">
                  <div className="form-floating mb-4 p-0">
                    <input
                      type="email"
                      className="form-control"
                      placeholder="Email address"
                      value={senderEmail}
                      onChange={(e) => setSenderEmail(e.target.value)}
                      required
                    />
                    <label htmlFor="senderEmail">Tài khoản người gửi (email)</label>
                  </div>
                </div>
                {/* Các trường khác tương tự */}
                <div className="row">
                  <div className="col-lg-6 col-md-6 col-12">
                    <div className="form-floating">
                      <input
                        type="number"
                        className="form-control"
                        placeholder="Số tiền"
                        value={amount}
                        onChange={(e) => setAmount(e.target.value)}
                        required
                      />
                      <label htmlFor="amount">Số tiền</label>
                    </div>
                  </div>
                  {/* Các trường khác tương tự */}
                  <div className="col-lg-6 col-6 mx-auto">
                    <button type="submit" className="form-control">Gửi</button>
                  </div>
                </div>
              </form>
            </div>
          </div>
        </div>
        <div className="video-wrap">
          <video autoPlay loop muted className="custom-video" poster="">
            <source src="videos/video.mp4" type="video/mp4" />
            Your browser does not support the video tag.
          </video>
        </div>
      </section>
    </main>
  );
}

ReactDOM.render(<App />, document.getElementById('root'));
