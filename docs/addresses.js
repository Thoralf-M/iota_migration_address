let converter
wasm.wasmmodule.then(r => converter = r)

async function convert_address() {
  try {
    let address = document.getElementById('address').value.trim()
    let converted = "";
    console.log(address);
    if (address.length > 80) {
      converted = await converter.convert_to_migration_address(address)
    } else {
      converted = await converter.convert_to_tryte_address(address)
    }
    addAddressElement(converted)
  } catch (e) {
    addAddressElement(e)
  }
}

function addAddressElement(address) {
  let addressElement = document.getElementById("converted_address");
  if (address.length > 80) {
    addressElement.innerHTML = "<pre>" + address + ' <a href="https://explorer.iota.org/mainnet/address/' + address + '" target="_blank" rel="noopener noreferrer">explorer</a><br>'
  } else {
    addressElement.innerHTML = "<pre>" + address + '<br>'

  }
}
