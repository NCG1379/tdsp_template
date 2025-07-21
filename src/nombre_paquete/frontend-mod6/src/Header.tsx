import React from 'react';
import './Header.css';
import LogoUnal from './assets/LogoUnal.png';

const Header: React.FC = () => (
  <header className="app-header">
    <div className="logo-container">
      <img src={LogoUnal} alt="Logo" className="logo-rect" />
    </div>
    <div className="header-content">
      <h1 className="tool-name">Proyecto Mod 6 MLDS</h1>
      <div className="dev-names">
        <span>José</span>
        <span>Diego</span>
        <span>Nicolás</span>
      </div>
    </div>
  </header>
);

export default Header;